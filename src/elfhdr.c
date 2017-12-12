#include <stdio.h>
#include <stdlib.h>
#include <linux/elf.h>
#include "elf_analyzer.h"

extern Elf64_Ehdr *p_ehdr64;

int
load_ehdr() {
    size_t ehdr_size = sizeof(Elf64_Ehdr);
    p_ehdr64 = (Elf64_Ehdr *)malloc(ehdr_size);
    fread(p_ehdr64, ehdr_size, 1, fp);
    return 0;
}
