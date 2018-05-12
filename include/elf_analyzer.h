#ifndef ELF_ANALYZER_INCLUDED
#define ELF_ANALYZER_INCLUDED

#include <stdio.h>
#include <linux/elf.h>

#define Elf_Byte __u8

#define PRINT_STC(ptr, name, format, suffix) \
    printf( #name ":\t"  #format #suffix "\n", (ptr) -> name )
#define PRINT_STC_WITH_NAME(ptr, name, format, suffix, val_name) \
    printf( #name ":\t%s ("  #format #suffix ")\n", val_name, (ptr) -> name)

#define FREE_IF_EXIST(ptr) \
    if ((ptr) != NULL) free(ptr)

void* load_elf(size_t size, Elf64_Off offset);
int read_elf(void *ptr, size_t size, Elf64_Off offset);

#endif
