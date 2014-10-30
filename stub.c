#include "sherlocked.h"
#include "md5.h"
#include <sys/prctl.h>

#define TMP_SCRIPT "/tmp/.sherlocked.script.123xyz"

payload_meta_t payload __attribute__((section(".data"))) = {0x00};
static int watermark = 0;
char *passwd = NULL;
int keylen;

static long _ptrace(long request, long pid, void *addr, void *data) 
{
        long ret;

        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
                        "mov %2, %%rdx\n"
                        "mov %3, %%r10\n"
                        "mov $101, %%rax\n"
                        "syscall" : : "g"(request), "g"(pid), "g"(addr), "g"(data));
        asm("mov %%rax, %0" : "=r"(ret));
        
        return ret;
}

static long _write(long fd, char *buf, unsigned long len)
{
        long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
                        "mov %2, %%rdx\n"
                        "mov $1, %%rax\n"
                        "syscall" : : "g"(fd), "g"(buf), "g"(len));
        asm("mov %%rax, %0" : "=r"(ret));
        return ret;
}

void bail_out(void)
{
	fprintf(stderr, "The gates of heaven remain closed\n");
	kill(getppid(), SIGKILL);
	kill(getpid(), SIGKILL);
	exit(-1);
}



void enable_anti_debug(void)
{	
	char buf[256];
	char *p;
	int val;

	FILE *fd = fopen("/proc/self/status", "r");
	while (fgets(buf, sizeof(buf), fd)) {
		if (!strstr(buf, "TracerPid")) 
			continue;
		fclose(fd);
		p = &buf[11];
		if (*p == '0') {
			watermark++;
			return;
		} else {
			bail_out();
		}
	}	
}

void decode_payload_struct(size_t len)
{
	size_t i;
	uint8_t *p;

	for (p = (uint8_t *)&payload, i = 0; i < len; i++) {
		*p ^= ((i << 0xE) & 0xFF);
		p++;
	}
}
 
		
void decode_payload_data(size_t len)
{
	size_t i, b;
	uint8_t *p;
	
	/*
	 * The program was supplied with the ability to self-decrypt
	 * without a user supplied key.
	 */
	if (payload.keylen) {
		for (p = (uint8_t *)payload.data, i = 0, b = 0; i < len; i++) {
			p[i] ^= payload.key[b++];
			if (b > payload.keylen - 1)
				b = 0;
		}
		goto done;
	}
	/*
	 * The program requires a key from the user to decrypt msg
	 */
	for (p = (uint8_t *)payload.data, i = 0, b = 0; i < len; i++) {
		p[i] ^= passwd[b++];
		if (b > keylen - 1)
			b = 0;
	}
	
done:
	return;
}		

void denied(void)
{
	bail_out();
}

void accepted(void)
{
	__asm__ __volatile__("nop\n");
}

void exec_cmd (char *str, ...)
{
        char string[1024];
        va_list va;

        va_start (va, str);
        vsnprintf (string, 1024, str, va);
        va_end (va);
        system (string);
}

#define CHUNK_SIZE 512

int main(int argc, char **argv, char **envp)
{
	MD5_CTX ctx;
	char path[256];
	uint8_t *mp, digest[16];
	struct stat st;
	size_t i, len, offset = 0;
	size_t total_plen = sizeof(payload);
	uint64_t a[2], x;
	void (*f)();
	int fd, ifd, pid;
	int status, ac;
	struct timeval tv;
	char **args;
	
	/*
 	 * Enable anti-debug code which performs
	 * self tracing with direct syscall ptrace
	 * code.
	 */
	enable_anti_debug();
	/*
	 * Decrypt the meta data 
	 */
	decode_payload_struct(total_plen);
	
	if (!payload.keylen) {
		if (argc < 2) {
			fprintf(stderr, "This message requires that you supply a key to decrypt\n");
			exit(0);
		}
		passwd = argv[1];
		keylen = strlen(passwd);
	}
	
	/*
	 * Decrypt the payload data
	 */
	decode_payload_data(payload.payload_len);
	
	/*
	 * Simple watermarking to see if antidebugging
	 * code was tampered with. If so, then exit.
	 */
	a[0] = (uint64_t)&denied;
	a[1] = (uint64_t)&accepted;
	x = a[!(!(watermark))];
	f = (void *)x;
	f(); 
	
	/*
	 * Validate interpreter
	 */
	

        ifd = open(payload.interp, O_RDONLY);
        if (ifd < 0) {
                fprintf(stderr, "Unable to open/validate interpreter\n");
                exit(-1);
        }
        fstat(ifd, &st);
        
        mp = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, ifd, 0);
        if (mp == MAP_FAILED) {
                fprintf(stderr, "Unable to mmap/validate interpreter: %s\n", strerror(errno));
                exit(-1);
        }

        MD5_Init(&ctx);
        MD5_Update(&ctx, mp, st.st_size);
        MD5_Final(digest, &ctx);
	
	close(ifd);

	if (memcmp(digest, payload.digest, 16) != 0) 
		bail_out();
	
	gettimeofday(&tv, NULL);
	srand(tv.tv_usec);
	snprintf(path, sizeof(path)-1, "%s.%d", TMP_SCRIPT, rand() % 8192);
	
        if (payload.keylen) { // meaning key is contained within binary
                              // so we support command line args being passed to script
                args = (char **)malloc(sizeof(char *) * (argc + 1));
		args[0] = (char *)payload.interp;
                args[1] = (char *)path;
                for (i = 2, ac = argc - 1; ac > 0; ac--, i++)
                        args[i] = strdup(argv[i - 1]); 	
		args[i] = NULL;
        }
	
	if ((fd = open(path, O_CREAT|O_TRUNC|O_RDWR, S_IRWXU)) < 0) {
		fprintf(stderr, "[!] Unable to generate script file\n");
		exit(-1);
	}
	
	
	
	/*
	 * Write the payload data to stdout
	 */
	offset = 0;
	len = payload.payload_len;
	do {
		if (len < CHUNK_SIZE) {
			_write(fd, (char *)&payload.data[offset], len);
			break;
		}
		_write(fd, (char *)&payload.data[offset], CHUNK_SIZE);
		offset += CHUNK_SIZE;
		len -= CHUNK_SIZE;
	}	while (len > 0);
	fsync(fd);
	close(fd);
	
	if (!payload.keylen) { // in this case we don't support command line args from script 
		pid = fork();
		if (pid == 0) {
			execl(payload.interp, path, path, NULL);
			exit(0);
		}
		wait(NULL);
	} else { // in this case cmdline args may be passed to the script
		pid = fork();
		if (pid == 0) {
			execve(payload.interp, args, envp);
			exit(0);
		}
		wait(NULL);
	}

	if (unlink(path) < 0) 
		fprintf(stderr, "Unable to ulink %s: %s\n", path, strerror(errno));

	exit(0);
	
}

