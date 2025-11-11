// SPDX-License-Identifier: BSD-3-Clause

#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>

#define PT_LOAD 1
#define _8MB 8388608
void *map_elf(const char *filename)
{
	// This part helps you store the content of the ELF file inside the buffer.
	struct stat st;
	void *file;
	int fd;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(1);
	}

	fstat(fd, &st);

	file = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (file == MAP_FAILED) {
		perror("mmap");
		close(fd);
		exit(1);
	}

	return file;
}

void load_and_run(const char *filename, int argc, char **argv, char **envp)
{
	// Contents of the ELF file are in the buffer: elf_contents[x] is the x-th byte of the ELF file.
	void *elf_contents = map_elf(filename);

	if (memcmp(elf_contents, "\177ELF", 4)) {
        fprintf(stderr, "Not a valid ELF file\n");
        exit(3);
    }

    if ((*((unsigned char *)elf_contents + 4)) != 2) {
        fprintf(stderr, "Not a 64-bit ELF\n");
        exit(4);
    }

    uint64_t e_phoff = *((uint64_t *)((unsigned char *)elf_contents + 32));
    uint16_t e_phentsize = *((uint16_t *)((unsigned char *)elf_contents + 54)); 
    uint16_t e_phnum = *((uint16_t *)((unsigned char *)elf_contents + 56));
    for (uint64_t i = e_phoff; i < e_phoff + e_phentsize * e_phnum; i += e_phentsize) {

        uint32_t p_type = *(uint32_t *)((unsigned char *)elf_contents + i + 0);
        uint32_t p_flags = *(uint32_t *)((unsigned char *)elf_contents + i + 4);
        uint64_t p_offset = *(uint64_t *)((unsigned char *)elf_contents + i + 8);
        uint64_t p_vaddr = *(uint64_t *)((unsigned char *)elf_contents + i + 16);
        uint64_t p_paddr = *(uint64_t *)((unsigned char *)elf_contents + i + 24);
        uint64_t p_filesz = *(uint64_t *)((unsigned char *)elf_contents + i + 32);
        uint64_t p_memsz = *(uint64_t *)((unsigned char *)elf_contents + i + 40);
        uint64_t p_align = *(uint64_t *)((unsigned char *)elf_contents + i + 48);

        unsigned char p_execute = (p_flags & 1);
        unsigned char p_write = (p_flags & 2) >> 1;
        unsigned char p_read = (p_flags & 4) >> 2;
        if (p_type == PT_LOAD) {
            void *addr = mmap((void *)(p_vaddr & ~0xFFF), (p_memsz) + (p_vaddr & 0xFFF ), (PROT_READ * 1) | (PROT_WRITE * 1 ) | (PROT_EXEC * 1), MAP_ANONYMOUS | MAP_PRIVATE, -1, 0); 
            if(addr == MAP_FAILED) { 
                printf("Failed\n"); 
                exit(13);
            }
            memcpy(addr + (p_vaddr & 0xFFF), (unsigned char *)elf_contents + p_offset, p_filesz);
            mprotect(addr, p_memsz + (p_paddr & 0XFFF), PROT_EXEC * p_execute | PROT_READ * p_read | PROT_WRITE * p_write);
        }
    }
	/*
	 * TODO: Support Static Non-PIE Binaries with libc
	 * Must set up a valid process stack, including:
	 *	- argc, argv, envp
	 *	- auxv vector (with entries like AT_PHDR, AT_PHENT, AT_PHNUM, etc.)
	 * Note: Beware of the AT_RANDOM, AT_PHDR entries, the application will crash if you do not set them up properly.
	 */

    // try without MAP_ANONYMOUS for fun
    void *sbp = mmap(NULL, _8MB, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    uint8_t *ssp = (uint8_t *)sbp + _8MB;
    uint64_t e_entry = *((uint64_t *)((unsigned char *)elf_contents + 24));
    uint64_t e_phdr = (uint64_t)elf_contents + e_phoff;
    
    uint32_t n_envc = 0;
    uint32_t s_size = 0;
    while (envp[n_envc]) {
        s_size += strlen(envp[n_envc]) + 1;
        n_envc++;
    }

    for (uint32_t i = 0; i < argc; i++) {
        s_size += strlen(argv[i]) + 1;
    }

    s_size += strlen(filename) + 1;

    uint32_t og_s_size = s_size;
    s_size = (s_size + 15) & ~15;

    // might be wrong 
    ssp -= s_size;

    for (uint8_t i = 0; i < s_size - og_s_size; i++) {
        *(ssp++) = rand() % 256; 
    }

    uint8_t *c_ssp = ssp;
    uint8_t **new_argv = malloc((argc + 1) * sizeof(uint8_t *));
    
    for (uint32_t i = 0; i < argc; i++) {
        uint32_t len = strlen(argv[i]) + 1;
        memcpy(c_ssp, argv[i], len);
        new_argv[i] = (uint8_t *)c_ssp;
        c_ssp += len;
    }
    new_argv[argc] = NULL;

    uint8_t **new_envp = malloc((n_envc + 1) * sizeof(uint8_t *));
    for (uint32_t i = 0; i < n_envc; i++) {
        uint32_t len = strlen(envp[i]) + 1;
        memcpy(c_ssp, envp[i], len);
        new_envp[i] = (uint8_t *)c_ssp;
        c_ssp += len;
    }
    new_envp[n_envc] = NULL;

    uint8_t *AT_EXECFN = (uint8_t *)c_ssp;
    memcpy(c_ssp, filename, strlen(filename) + 1);

    // finished the top now we go back with ssp from before we started allocating
    // strings

    ssp -= strlen("x86_64\0");
    uint8_t *AT_PLATFORM = (uint8_t *)ssp;
    memcpy(ssp, "x86_64", 7);

    ssp -= 16;
    uint8_t *AT_RANDOM = ssp;
    for (uint32_t i = 0; i < 16; i++) {
        AT_RANDOM[i] = rand() % 256;
    }

    ssp -= (uint64_t)ssp % 16;

    ssp -= 8; *((uint64_t *)ssp) = 0;
    ssp -= 8; *((uint64_t *)ssp) = 0;

    ssp -= 8; *((uint64_t *)ssp) = (uint64_t)AT_PLATFORM;
    ssp -= 8; *((uint64_t *)ssp) = 15;

    ssp -= 8; *((uint64_t *)ssp) = (uint64_t)AT_EXECFN;
    ssp -= 8; *((uint64_t *)ssp) = 31;

    ssp -= 8; *((uint64_t *)ssp) = (uint64_t)AT_RANDOM;
    ssp -= 8; *((uint64_t *)ssp) = 25;

    ssp -= 8; *((uint64_t *)ssp) = 0;
    ssp -= 8; *((uint64_t *)ssp) = 23;

    ssp -= 8; *((uint64_t *)ssp) = getegid();
    ssp -= 8; *((uint64_t *)ssp) = 14;

    ssp -= 8; *((uint64_t *)ssp) = getgid();
    ssp -= 8; *((uint64_t *)ssp) = 13;

    ssp -= 8; *((uint64_t *)ssp) = geteuid();
    ssp -= 8; *((uint64_t *)ssp) = 12;

    ssp -= 8; *((uint64_t *)ssp) = getuid();
    ssp -= 8; *((uint64_t *)ssp) = 11;

    ssp -= 8; *((uint64_t *)ssp) = e_entry;
    ssp -= 8; *((uint64_t *)ssp) = 9;

    ssp -= 8; *((uint64_t *)ssp) = 0;
    ssp -= 8; *((uint64_t *)ssp) = 8;

    ssp -= 8; *((uint64_t *)ssp) = 0;
    ssp -= 8; *((uint64_t *)ssp) = 7;

    ssp -= 8; *((uint64_t *)ssp) = e_phnum;
    ssp -= 8; *((uint64_t *)ssp) = 5;

    ssp -= 8; *((uint64_t *)ssp) = e_phentsize;
    ssp -= 8; *((uint64_t *)ssp) = 4;

    ssp -= 8; *((uint64_t *)ssp) = e_phdr;
    ssp -= 8; *((uint64_t *)ssp) = 3;

    ssp -= 8; *((uint64_t *)ssp) = 100;
    ssp -= 8; *((uint64_t *)ssp) = 17;

    ssp -= 8; *((uint64_t *)ssp) = 4096;
    ssp -= 8; *((uint64_t *)ssp) = 6;

    ssp -= 8; *((uint64_t *)ssp) = 0xbfebfbff;
    ssp -= 8; *((uint64_t *)ssp) = 16;

    ssp -= 8; *((uint64_t *)ssp) = 0x7fff6c86b000;
    ssp -= 8; *((uint64_t *)ssp) = 33;

    ssp -= 8; *((uint64_t *)ssp) = 0;
    for (int i = 0; i < n_envc; i++) {
        ssp -= 8;
        *((uint64_t *)ssp) = (uint64_t)new_envp[i];
    }

    ssp -= 8; *((uint64_t *)ssp) = 0;
    for (int i = 0; i < argc; i++) {
        ssp -= 8;
        *((uint64_t *)ssp) = (uint64_t)new_argv[i];
    }

    ssp -= 8;
    *((uint64_t *)ssp) = argc;
    
    free(new_argv);
    free(new_envp);

    void (*entry)() = (void (*)())e_entry;
    //void (*entry)() = (void (*)())(*((uint64_t *)((unsigned char *)elf_contents + 24)));
	/**
	 * TODO: Support Static PIE Executables
	 * Map PT_LOAD segments at a random load base.
	 * Adjust virtual addresses of segments and entry point by load_base.
	 * Stack setup (argc, argv, envp, auxv) same as above.
	 */

    //((void (*)())(*((uint64_t *)((unsigned char *)elf_contents + 24))))();

	// Transfer control
	__asm__ __volatile__(
			"mov %0, %%rsp\n"
			"xor %%rbp, %%rbp\n"
			"jmp *%1\n"
			:
			: "r"(ssp), "r"(entry)
			: "memory"
			);
}

int main(int argc, char **argv, char **envp)
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <static-elf-binary>\n", argv[0]);
		exit(1);
	}

	load_and_run(argv[1], argc - 1, &argv[1], envp);
	return 0;
}


