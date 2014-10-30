/*
 * AFMe -> Anti-forensics messaging execution
 * <elfmaster@zoho.com> Ryan O'Neill 2014
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <elf.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <stdarg.h>

#define MAX_INTERP_LEN 256
#define MAX_KEY_SIZE 255
#define KEY_BUF_LEN 256
#define MAX_PAYLOAD_SIZE ((1024 * 1024) * 2)

typedef struct payload_meta {
        uint64_t payload_len;
        uint32_t keylen;
	char interp[MAX_INTERP_LEN];
        uint8_t key[KEY_BUF_LEN];
	uint8_t digest[16];
        uint8_t data[MAX_PAYLOAD_SIZE];
} payload_meta_t;


