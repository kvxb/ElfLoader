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
	void *elf_contents = map_elf(filename);

	if (memcmp(elf_contents, "\177ELF", 4)) {
		fprintf(stderr, "Not a valid ELF file\n");
		exit(3);
	}

	if ((*((uint8_t *)elf_contents + 4)) != 2) {
		fprintf(stderr, "Not a 64-bit ELF\n");
		exit(4);
	}

	uint16_t e_type = *((uint16_t *)((uint8_t *)elf_contents + 16));
	int32_t is_pie = (e_type == 3);
	uint64_t e_entry = *((uint64_t *)((uint8_t *)elf_contents + 24));
	uint64_t e_phoff = *((uint64_t *)((uint8_t *)elf_contents + 32));
	uint16_t e_phentsize = *((uint16_t *)((uint8_t *)elf_contents + 54));
	uint16_t e_phnum = *((uint16_t *)((uint8_t *)elf_contents + 56));

	int64_t pagesz = sysconf(_SC_PAGESIZE);
	uint64_t load_base = 0;
	uint64_t v_entry = e_entry;
	uint64_t v_phdr = (uint64_t)elf_contents + e_phoff;

	if (is_pie) {
		uint64_t min_vaddr = UINT64_MAX;
		uint64_t max_vaddr = 0;

		for (uint16_t i = 0; i < e_phnum; i++) {
			uint64_t off = e_phoff + (uint64_t)i * e_phentsize;
			uint32_t p_type = *(uint32_t *)((uint8_t *)elf_contents + off + 0);
			uint64_t p_vaddr = *(uint64_t *)((uint8_t *)elf_contents + off + 16);
			uint64_t p_memsz = *(uint64_t *)((uint8_t *)elf_contents + off + 40);

			if (p_type == PT_LOAD) {
				if (p_vaddr < min_vaddr)
					min_vaddr = p_vaddr;
				if (p_vaddr + p_memsz > max_vaddr)
					max_vaddr = p_vaddr + p_memsz;
			}
		}

		uint64_t span = (max_vaddr - min_vaddr + pagesz - 1) & ~(pagesz - 1);
		void *reserved = mmap(NULL, span, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

		load_base = (uint64_t)reserved - min_vaddr;
		v_entry = e_entry + load_base;

		for (uint16_t i = 0; i < e_phnum; i++) {
			uint64_t off = e_phoff + (uint64_t)i * e_phentsize;
			uint32_t p_type = *(uint32_t *)((uint8_t *)elf_contents + off + 0);
			uint64_t p_vaddr = *(uint64_t *)((uint8_t *)elf_contents + off + 16);
			uint64_t p_offset = *(uint64_t *)((uint8_t *)elf_contents + off + 8);
			uint64_t p_filesz = *(uint64_t *)((uint8_t *)elf_contents + off + 32);

			if (p_type == PT_LOAD) {
				if (p_offset <= e_phoff && e_phoff < p_offset + p_filesz) {
					v_phdr = load_base + p_vaddr + (e_phoff - p_offset);
					break;
				}
			}
		}
	}

	for (uint64_t i = e_phoff; i < e_phoff + e_phentsize * e_phnum; i += e_phentsize) {
		uint32_t p_type = *(uint32_t *)((uint8_t *)elf_contents + i + 0);
		uint32_t p_flags = *(uint32_t *)((uint8_t *)elf_contents + i + 4);
		uint64_t p_offset = *(uint64_t *)((uint8_t *)elf_contents + i + 8);
		uint64_t p_vaddr = *(uint64_t *)((uint8_t *)elf_contents + i + 16);
		uint64_t p_paddr = *(uint64_t *)((uint8_t *)elf_contents + i + 24);
		uint64_t p_filesz = *(uint64_t *)((uint8_t *)elf_contents + i + 32);
		uint64_t p_memsz = *(uint64_t *)((uint8_t *)elf_contents + i + 40);

		uint8_t p_execute = (p_flags & 1);
		uint8_t p_write = (p_flags & 2) >> 1;
		uint8_t p_read = (p_flags & 4) >> 2;

		if (p_type == PT_LOAD) {
			uint64_t seg_vaddr = p_vaddr + load_base;

			if (is_pie) {
				uint64_t seg_page_start = seg_vaddr & ~(uint64_t)(pagesz - 1);
				uint64_t headroom = seg_vaddr - seg_page_start;
				uint64_t alloc_size = (headroom + p_memsz + pagesz - 1) & ~(pagesz - 1);

				void *m = mmap((void *)seg_page_start, alloc_size,
					       PROT_READ | PROT_WRITE,
					       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
					       -1, 0);
				if (m == MAP_FAILED) {
					perror("mmap segment");
					exit(13);
				}

				if (p_filesz)
					memcpy((void *)seg_vaddr, (uint8_t *)elf_contents + p_offset, p_filesz);

				if (p_memsz > p_filesz)
					memset((void *)(seg_vaddr + p_filesz), 0, p_memsz - p_filesz);

				int32_t prot = 0;

				if (p_flags & 4)
					prot |= PROT_READ;
				if (p_flags & 2)
					prot |= PROT_WRITE;
				if (p_flags & 1)
					prot |= PROT_EXEC;
				if (mprotect((void *)seg_page_start, alloc_size, prot) == -1) {
					perror("mprotect");
					exit(13);
				}
			} else {
				void *addr = mmap((void *)(seg_vaddr & ~0xFFF),
						 p_memsz + (seg_vaddr & 0xFFF),
						 PROT_READ | PROT_WRITE | PROT_EXEC,
						 MAP_ANONYMOUS | MAP_PRIVATE | (is_pie ? 0 : MAP_FIXED),
						 -1, 0);
				if (addr == MAP_FAILED) {
					printf("Failed to map segment\n");
					exit(13);
				}
				memcpy(addr + (seg_vaddr & 0xFFF), (uint8_t *)elf_contents + p_offset, p_filesz);
				mprotect(addr, p_memsz + (p_paddr & 0xFFF),
					 PROT_EXEC * p_execute | PROT_READ * p_read | PROT_WRITE * p_write);
			}
		}
	}

	void *bp = mmap(NULL, _8MB, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (bp == MAP_FAILED) {
		perror("mmap stack");
		exit(14);
	}

	uint8_t *sp = (uint8_t *)bp + _8MB;

	uint32_t n_envc = 0;

	while (envp[n_envc])
		n_envc++;

	sp -= strlen(filename) + 1;
	uint8_t *AT_EXECFN = (uint8_t *)sp;

	memcpy(sp, filename, strlen(filename) + 1);

	uint8_t **new_argv = malloc((argc + 1) * sizeof(uint8_t *));

	for (int32_t i = argc - 1; i >= 0; i--) {
		uint32_t len = strlen(argv[i]) + 1;

		sp -= len;
		memcpy(sp, argv[i], len);
		new_argv[i] = (uint8_t *)sp;
	}
	new_argv[argc] = NULL;

	uint8_t **new_envp = malloc((n_envc + 1) * sizeof(uint8_t *));

	for (int32_t i = n_envc - 1; i >= 0; i--) {
		uint32_t len = strlen(envp[i]) + 1;

		sp -= len;
		memcpy(sp, envp[i], len);
		new_envp[i] = (uint8_t *)sp;
	}
	new_envp[n_envc] = NULL;

	sp--;
	while ((uint64_t)sp % 16 != 0)
		*(sp--) = rand() % 256;

	sp -= strlen("x86_64\0");
	uint8_t *AT_PLATFORM = (uint8_t *)sp;

	memcpy(sp, "x86_64", 7);

	sp -= 16;
	uint8_t *AT_RANDOM = sp;

	for (uint32_t i = 0; i < 16; i++)
		AT_RANDOM[i] = rand() % 256;

	sp -= (uint64_t)sp % 16;

	sp -= 8; *((uint64_t *)sp) = 0;
	sp -= 8; *((uint64_t *)sp) = 0;

	sp -= 8; *((uint64_t *)sp) = (uint64_t)AT_PLATFORM;
	sp -= 8; *((uint64_t *)sp) = 15;

	sp -= 8; *((uint64_t *)sp) = (uint64_t)AT_EXECFN;
	sp -= 8; *((uint64_t *)sp) = 31;

	sp -= 8; *((uint64_t *)sp) = (uint64_t)AT_RANDOM;
	sp -= 8; *((uint64_t *)sp) = 25;

	sp -= 8; *((uint64_t *)sp) = 0;
	sp -= 8; *((uint64_t *)sp) = 23;

	sp -= 8; *((uint64_t *)sp) = getegid();
	sp -= 8; *((uint64_t *)sp) = 14;

	sp -= 8; *((uint64_t *)sp) = getgid();
	sp -= 8; *((uint64_t *)sp) = 13;

	sp -= 8; *((uint64_t *)sp) = geteuid();
	sp -= 8; *((uint64_t *)sp) = 12;

	sp -= 8; *((uint64_t *)sp) = getuid();
	sp -= 8; *((uint64_t *)sp) = 11;

	sp -= 8; *((uint64_t *)sp) = v_entry;
	sp -= 8; *((uint64_t *)sp) = 9;

	sp -= 8; *((uint64_t *)sp) = 0;
	sp -= 8; *((uint64_t *)sp) = 8;

	sp -= 8; *((uint64_t *)sp) = 0;
	sp -= 8; *((uint64_t *)sp) = 7;

	sp -= 8; *((uint64_t *)sp) = e_phnum;
	sp -= 8; *((uint64_t *)sp) = 5;

	sp -= 8; *((uint64_t *)sp) = e_phentsize;
	sp -= 8; *((uint64_t *)sp) = 4;

	sp -= 8; *((uint64_t *)sp) = v_phdr;
	sp -= 8; *((uint64_t *)sp) = 3;

	sp -= 8; *((uint64_t *)sp) = 100;
	sp -= 8; *((uint64_t *)sp) = 17;

	sp -= 8; *((uint64_t *)sp) = pagesz;
	sp -= 8; *((uint64_t *)sp) = 6;

	sp -= 8; *((uint64_t *)sp) = 0xbfebfbff;
	sp -= 8; *((uint64_t *)sp) = 16;

	sp -= 8; *((uint64_t *)sp) = 0;

	for (int32_t i = n_envc - 1; i >= 0; i--) {
		sp -= 8;
		*((uint64_t *)sp) = (uint64_t)new_envp[i];
	}

	sp -= 8; *((uint64_t *)sp) = 0;
	for (int32_t i = argc - 1; i >= 0; i--) {
		sp -= 8;
		*((uint64_t *)sp) = (uint64_t)new_argv[i];
	}

	sp -= 8; *((uint64_t *)sp) = argc;

	free(new_argv);
	free(new_envp);

	void (*entry)() = (void (*)())v_entry;

	__asm__ __volatile__(
		"mov %0, %%rsp\n"
		"xor %%rbp, %%rbp\n"
		"jmp *%1\n"
		:
		: "r"(sp), "r"(entry)
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
