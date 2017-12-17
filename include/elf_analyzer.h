#ifndef ELF_ANALYZER_INCLUDED
#define ELF_ANALYZER_INCLUDED

#include <stdio.h>
#include <linux/elf.h>

#include "analy_elf.h"
#include "analy_sec.h"
#include "analy_seg.h"
#include "analy_utils.h"

#define PRINT_STC(ptr, name, format, suffix) \
    printf( #name ":\t"  #format #suffix "\n", ptr -> name );

#define FREE_IF_EXIST(ptr) \
    if ((ptr) != NULL) free(ptr);

void* load_elf(size_t size, Elf64_Off offset);
int read_elf(void *ptr, size_t size, Elf64_Off offset);

#endif
