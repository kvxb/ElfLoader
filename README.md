# ELF Loader Assignment

## Objecives

* Practice working with virtual memory, memory protection, and manual relocation.
* Understand the difference between different types of executables, like PIE, non-PIE, staticly-linked, etc.
* Understand the stack layout expected by an executable, environment variables, auxiliary vector, command-line arguments, etc.

## Statement

Implement a custom minimal ELF loader, capabale of loading and executing statically linked binaries in Linux.

Your loader must eventually support:

* Minimal static binaries that make direct Linux syscalls (without libc)
* Statically linked **non-PIE** C programs using `libc`
* Statically linked **PIE** executables

## Support Code

The support code consists of three directories:

* `src/` where you will create your sollution
* `test/` contains the test suite and a Python script to verify your work

The test suite consists of source code files (`.c` and `.asm`), that will be compiled and then executed using your loader.
You can use the `Makefile` to compile all test files.

## Implementation

The assignment is split into **4 graded parts**, totaling **90 points** (10 points are given by the linter):

### 1. Minimal loader for syscall-only binaries (**10 points**)

**Goal:** Make the loader work with extremely minimal ELF binaries (usually written in assembly) that make direct syscalls and do not use libc.

* All memory segments can be loaded with `RWX` permissions.
* No need to set up `argv`, `envp`, or auxiliary vectors.
* These binaries call syscall instructions directly, so `libc` is not used.

For this task, you will need to:

* Open the file and map it somewhere in the memory
* Validate the ELF file (parse the header, check that it is an ELF file)
* Pass through the section headers, and for the `PT_LOAD` sections create new memory regions (they can have RWX permissions for now), then copy the section from the file into the newly created memory region.
* Pass the execution to the new ELF, by jumping to the entry point.

**Examples/Resources:**

* [ELF Specification](https://refspecs.linuxbase.org/elf/gabi4+/ch5.pheader.html)

### 2. Load memory regions with correct permissions (**20 points**)

**Goal:** Instead of RWX, check the memory protection flags (`PF_R`, `PF_W`, `PF_X`) from the ELF `Program Headers`.

* Use `mprotect()` or map with the correct permissions directly using `mmap()`.

**Key Concepts:**

* `PT_LOAD` program headers contain `p_flags` to specify memory permissions.
* These must be respected to mimic the kernel loader.
* [ELF Specification](https://refspecs.linuxbase.org/elf/gabi4+/ch5.pheader.html)

### 3. Support static non-PIE binaries with libc (**30 points**)

**Goal:** Load and run statically linked **non-PIE** C binaries compiled with libc (e.g., via `gcc -static`).

* Must set up a valid process **stack**, including:

  * `argc`, `argv`, `envp`
  * `auxv` vector (with entries like `AT_PHDR`, `AT_PHENT`, `AT_PHNUM`, etc.)

For this, you need to map a new memory region, that will become the new stack, then copy all the required information there.

The executable expects the stack layout as seen in the figure below:

![Stack Layout](./img/stack-layout.drawio.svg)

You can see more details about the stack [here](https://lwn.net/Articles/631631/).

You will have to reserve a memory region large enough for the stack (you can use the maximum allowed stack size, using `getrlimit`, or you can use a harcoded value large enough to fit everything).
After that, you need to copy the argc, argv and envp in the expected layout, then set up the auxv.

**Note:** `argv` and `envp`, since they consist of strings, will be placed as the **pointer to the string** on the stack, not the string itself.

#### argc, argv (5 points out of 30)

The command line arguments must be placed first at the top of the stack, as seen in the picture above.
The loader can be used as `./elf_loader ./no-pie-exec arg1 arg2 arg3`.
`arg1`, `arg2` and `arg3` must be placed on the stack for the loaded executable.
`argc` will be also placed on the at the top of the stack.

#### envp (5 points out of 30)

The environment variables should be placed after the command line arguments.
For this, you just have to copy everything from the `char **envp` array and place it on the stack.

#### auxv (10 points out of 30)

The auxiliary vector, auxv, is a mechanism for communicating information from the kernel to user space.
It's basically a list of key-value pairs that contains different information about the state of the executable.
You can see the keys and required values of the auxv [in the man pages](https://man7.org/linux/man-pages/man3/getauxval.3.html).
For example, for the key `AT_PAGESZ` (defined as 6 in [elf.h](https://elixir.bootlin.com/glibc/glibc-2.42.9000/source/elf/elf.h#L1205)), that needs to contain the value of the page size, the memory will look as follows:

```text
0xfff......    --> High Addresses
-----------
  4096         # Page Size
   6           # AT_PAGESZ key
-----------
-----------
0x000......    --> Low Addresses
```

The auvx must end with an `AT_NULL` key with a 0 value, so an auxv that sets `AT_PAGESZ`, `AT_UID` and `AT_NULL` will look like this on the stack:

![Auxv Example](./img/auxv-example.drawio.svg)

__Note:__ Beware of the `AT_RANDOM` entry, the application will crash if you do not set it up properly.

**Docs:**

* [How programs get run: ELF binaries](https://lwn.net/Articles/631631/) (See section: `Populating the stack`)
* [auxv man page](https://man7.org/linux/man-pages/man3/getauxval.3.html)

### 4. Support static PIE executables (**30 points**)

**Goal:** Make your loader support static **PIE (Position Independent Executable)** binaries.

* ELF type will be `ET_DYN`, and segments must be mapped at a **random base address**.
* Entry point and memory segment virtual addresses must be adjusted by the `load_base`.

**Additional Requirements:**

* Must still build a valid stack (`argc`, `argv`, `auxv`, etc.)
* Handle relocation of entry point and program headers correctly.

You will need to load all the segments at a random offset.
Beware of the auxv entries, some of them will need to be adjusted to the offset.

**Docs:**

* [What is a PIE binary?](https://eli.thegreenplace.net/2011/08/25/load-time-relocation-of-shared-libraries)
* [Example ELF Loader](https://0xc0ffee.netlify.app/osdev/22-elf-loader-p2)
* [Another ELF Loader Example](https://www.mgaillard.fr/2021/04/15/load-elf-user-mode.html)

## Debugging

Here are some useful tips and tools to debug your ELF loader:

### General Tips

* **Start simple**: First test with a syscall-only ELF binary (e.g., `write` + `exit`).
* **Use GDB**: Run `gdb ./elf_loader` and set breakpoints in the loader and inside the loaded ELF. You can use `add-symbol-file path-to-elf start-address` to debug the libc entry and the elf execution with debugging symbols.
* **Check memory layout**: Print segment addresses and protections. You can use `pmap $(pidof elf-loader)`

### Useful Tools

* `readelf -l -h your_binary`
* `objdump -d your_binary`
* `gdb ./elf_loader`
* `pmap $(pidof elf_loader)`

## Compilation Tips

To start the testing, run `make check` in the `tests/` directory.
You can modify the source files in `tests/snippets` and try different things.
To run the loader manually, use `./elf-loader ../tests/snippets/<test-name> arg1 arg2 ...`.
