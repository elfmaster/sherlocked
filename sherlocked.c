#include "sherlocked.h"
#include "stub_shellcode.h"
#include "md5.h"

#define TMP_PATH "/tmp/.afm.stub"

int requires_user_key = 0;

void encode_payload_data(uint8_t *data, size_t len, uint8_t *key, int keylen)
{
	size_t i, b;
	uint8_t *p = data;

	for (b = 0, i = 0; i < len; i++) {
		p[i] ^= key[b++];
		if (b > keylen - 1)
			b = 0;
	}
}

void encode_payload_struct(payload_meta_t *payload)
{
	size_t i, len = sizeof(payload_meta_t);
	uint8_t *p;

	for (p = (uint8_t *)payload, i = 0; i < len; i++) {
                *p ^= ((i << 0xE) & 0xFF);
                p++;
        }
}

char * get_section_index(int section, uint8_t *target)
{
        
        int i;
        Elf64_Ehdr *ehdr = (Elf64_Ehdr *)target;
        Elf64_Shdr *shdr = (Elf64_Shdr *)(target + ehdr->e_shoff);
        
        for (i = 0; i < ehdr->e_shnum; i++) {
                if (i == section)
                        return (target + shdr[i].sh_offset);
        }

}

void run_cmd(char *str, ...)
{
        char string[255];
        va_list va;

        va_start (va, str);
        vsnprintf (string, 255, str, va);
        va_end (va);

        system(string);
}

Elf64_Addr resolve_symbol(char *name, uint8_t *target)
{
        Elf64_Sym *symtab;
        char *SymStrTable;
        int i, j, symcount;

        Elf64_Off strtab_off;
        Elf64_Ehdr *ehdr = (Elf64_Ehdr *)target;
        Elf64_Shdr *shdr = (Elf64_Shdr *)(target + ehdr->e_shoff);

        for (i = 0; i < ehdr->e_shnum; i++) {
                if (shdr[i].sh_type == SHT_SYMTAB || shdr[i].sh_type == SHT_DYNSYM) {
                        SymStrTable = (char *)get_section_index(shdr[i].sh_link, target);
                        symtab = (Elf64_Sym *)get_section_index(i, target);
                        for (j = 0; j < shdr[i].sh_size / sizeof(Elf64_Sym); j++, symtab++) {
                                if(strcmp(&SymStrTable[symtab->st_name], name) == 0) {
                                        return (symtab->st_value);
                                }
                        }
                }
        }
        return 0;
} 

#define CHUNK_SIZE 64000 

int build_msg_program(uint8_t *payload, char *outfile)
{
	int fd, i;
	struct stat st;
	size_t stublen = sizeof(stub_shellcode);
	Elf64_Ehdr *ehdr;
	Elf64_Shdr *shdr;
	Elf64_Phdr *phdr;
	Elf64_Addr dataVaddr = 0;
	Elf64_Off dataOffset, offset, stuboff;
	Elf64_Addr symval;
	uint8_t *mem;
	
	if ((fd = open(TMP_PATH, O_TRUNC|O_RDWR|O_CREAT, NULL)) < 0) {
		perror("open");
		goto failure;
	}
	
	fchmod(fd, S_IXUSR|S_IRUSR|S_IWUSR); 
	
	stuboff = 0;
	size_t len = stublen;
        do {
		if (len < CHUNK_SIZE) {
			write(fd, (char *)&stub_shellcode[stuboff], len);
			break;
		}
                write(fd, (char *)&stub_shellcode[stuboff], CHUNK_SIZE);
                stuboff += CHUNK_SIZE;
                len -= CHUNK_SIZE;
        }       while (len > 0);
	syncfs(fd);
	close(fd);
	
	if ((fd = open(TMP_PATH, O_RDWR)) < 0) {
		perror("open");
		goto failure;
	}
	
	if (fstat(fd, &st) < 0) {
		perror("fstat");
		goto failure;
	}

	mem = mmap(NULL, (stublen + 4095) & ~4095, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (mem == MAP_FAILED) {
		perror("mmap");
		goto failure;
	}
		
	
	ehdr = (Elf64_Ehdr *)mem;
	shdr = (Elf64_Shdr *)(mem + ehdr->e_shoff);
	phdr = (Elf64_Phdr *)(mem + ehdr->e_phoff);

	for (i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_type == PT_LOAD && phdr[i].p_offset != 0) {
			dataVaddr = phdr[i].p_vaddr;
			dataOffset = phdr[i].p_offset;
			break;
		}
	}

	if (dataVaddr == 0) {
		fprintf(stderr, "Unable to find data segment in stub\n");
		goto failure;
	}
	
	symval = resolve_symbol("payload", mem);
	if (symval == 0) {
		fprintf(stderr, "Unable to locate symbol 'payload'\n");
		goto failure;
	}

	offset = symval - dataVaddr;
	offset += dataOffset;
	
	memcpy((void *)&mem[offset], payload, sizeof(payload_meta_t));
	
	if (msync(mem, stublen, MS_SYNC) < 0) {
		perror("msync");
		goto failure;
	}

	munmap(mem, stublen);
	close(fd);

	run_cmd("cp %s %s", TMP_PATH, outfile);
	run_cmd("strip %s", outfile);
	
	if (!access("utils/stripx", X_OK)) {
                printf("[+] utils/stripx exists, so using it to strip section headers off of DRM archive\n");
                run_cmd("utils/stripx %s", outfile);
        }

	if (!access("/usr/bin/upx", X_OK)) {
		printf("[+] /usr/bin/upx exists, so using it to compress %s\n", outfile);
		run_cmd("/usr/bin/upx %s", outfile);
	}
	
	unlink(TMP_PATH);
	return 0;

failure:
	unlink(TMP_PATH);
	return -1;
	
}

		
int main(int argc, char **argv)
{
	uint8_t *src, *dst;
	Elf64_Ehdr *ehdr;
	Elf64_Shdr *shdr;
        MD5_CTX ctx;

	struct stat st;
	char *infile, *outfile, *key;
	int keylen, fd;
	size_t i;
	
	payload_meta_t *payload;

	if (argc < 5) {
		printf("Usage: %s <infile> <outfile> <key> <interpreter> [-r]\n", argv[0]);
		exit(0);
	}
	
	int ifd;
	struct stat ist;
	uint8_t digest[64];

	ifd = open(argv[4], O_RDONLY);
	if (ifd < 0) {
		fprintf(stderr, "Unable to open/validate interpreter\n");
		exit(-1);
	}
	fstat(ifd, &ist);
	
	uint8_t *mp = mmap(NULL, ist.st_size, PROT_READ, MAP_PRIVATE, ifd, 0);
	if (mp == MAP_FAILED) {
		fprintf(stderr, "Unable to mmap/validate interpreter: %s\n", strerror(errno));
		exit(-1);
	}

	MD5_Init(&ctx);
	MD5_Update(&ctx, mp, ist.st_size);
	MD5_Final(digest, &ctx);
	
	close(ifd);

	if (argc > 5) {
		if (argv[5][0] == '-' && argv[5][1] == 'r') {
			printf("[+] Warning... password protected files aren't compatible with scripts that require command line args\n");
			printf("[+] The user who executes %s must supply password: %s\n", argv[2], argv[3]);
			requires_user_key++;
		} else {
			fprintf(stderr, "Unknown option: %s\n", argv[4]);
			exit(0);
		}
	}

	infile = argv[1];
	outfile = argv[2];
	key = argv[3];
	keylen = strlen(key);
	
	if ((payload = malloc(sizeof(payload_meta_t) + 4096)) == NULL) {
		perror("malloc");
		exit(-1);
	}
	
	memcpy((uint8_t *)payload->digest, digest, 16);

	if ((fd = open(infile, O_RDONLY)) < 0) {
		perror("open");
		exit(-1);
	}

	if (fstat(fd, &st) < 0) {
		perror("fstat");
		exit(-1);
	}

	src = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (src == MAP_FAILED) {
		perror("mmap");
		exit(-1);
	}
	
	/*
	 * If the user must supply a key to decrypt it, then the key
	 * will not be stored in the payload meta data
	 */
	if (!requires_user_key) {
		payload->keylen = keylen;
		if (payload->keylen > MAX_KEY_SIZE) {
			fprintf(stderr, "[!] Key must be no greater than %d bytes\n", MAX_KEY_SIZE);
			exit(0);
		}
		strcpy(payload->key, key);
	}

	payload->payload_len = st.st_size;
	strncpy(payload->interp, argv[4], 255);

	memcpy((char *)payload->data, (char *)src, st.st_size);
	
	printf("[+] Encoding payload data\n");
	encode_payload_data(payload->data, payload->payload_len, key, keylen);

	printf("[+] Encoding payload struct\n");
	encode_payload_struct(payload);
	
	printf("[+] Building msg program\n");
	build_msg_program((uint8_t *)payload, outfile);
	
	close(fd);
	
	printf("Successfully created %s\n", outfile);
	exit(0);
}

