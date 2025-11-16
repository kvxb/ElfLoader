# ELF Loader

### A custom minimal ELF loader implementation capable of loading and executing statically linked binaries in Linux. This project demonstrates low-level system programming concepts including virtual memory management, memory protection, and manual ELF relocation.

## Features

ELF Validation: Verifies ELF magic and 64-bit architecture

Multi-Format Support: Handles various executable types:

Minimal syscall-only binaries

Statically linked non-PIE C programs

Statically linked PIE (Position Independent Executable) binaries

Proper Memory Management: Implements correct memory protection flags (RWX) from ELF program headers

Stack Setup: Constructs proper process stack with command-line arguments, environment variables, and auxiliary vectors

## Implementation Details

ELF Header Validation

The loader performs initial validation checking for:

Valid ELF magic bytes

64-bit ELF class (ELFCLASS64)
Invalid files are rejected with appropriate error codes.

## Memory Segment Loading

Loads PT_LOAD segments with correct permissions from program headers

Uses mmap() and mprotect() to set up memory regions with proper RWX flags

Handles differences between file size and memory size (p_filesz vs p_memsz)

## Stack Construction

For C programs, the loader builds a complete stack layout including:

Command-line arguments (argc, argv)

Environment variables (envp)

Auxiliary vector (auxv) with entries like:

AT_PHDR, AT_PHENT, AT_PHNUM for program header information

AT_PAGESZ for system page size

AT_RANDOM for security entropy

AT_NULL terminator

## PIE Support

Handles position-independent executables by loading segments at random base addresses

Adjusts entry points and program header addresses relative to load base

Maintains proper stack setup even with relocated addresses

## Technical Insights

This project provides practical understanding of:

ELF file format and program headers

Virtual memory management and protection

Process initialization and stack layout

Difference between PIE and non-PIE binaries

Manual relocation and position-independent code

Linux system programming with direct syscalls

The implementation serves as an educational resource for understanding how executable files are loaded and executed at the system level, bridging the gap between high-level compilation and low-level execution.
