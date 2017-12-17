#include <stdio.h>
#include <stdlib.h>
#include <linux/elf.h>

#include "elf_analyzer.h"
#include "analy_elf.h"

static Elf64_Ehdr *p_ehdr64 = NULL;

int
load_ehdr() {
    size_t ehdr_size = sizeof(Elf64_Ehdr);
    p_ehdr64 = load_elf(ehdr_size, 0);
    return 0;
}

int
release_ehdr() {
    FREE_IF_EXIST(p_ehdr64);
    return 0;
}

const Elf64_Ehdr*
get_ehdr() {
    return p_ehdr64;
}

int
print_ehdr() {
    printf("--- ELF HEADER ---\n");
    if (p_ehdr64 == NULL) {
        printf("No entry exists\n");
        return -1;
    }
    PRINT_STC(p_ehdr64, e_type, %hx, h);
    PRINT_STC(p_ehdr64, e_machine, %hx, h);
    PRINT_STC(p_ehdr64, e_version, %d, );
    PRINT_STC(p_ehdr64, e_entry, %llx, h);
    PRINT_STC(p_ehdr64, e_phoff, %llx, h);
    PRINT_STC(p_ehdr64, e_shoff, %llx, h);
    PRINT_STC(p_ehdr64, e_flags, %x, h);
    PRINT_STC(p_ehdr64, e_ehsize, %hd, );
    PRINT_STC(p_ehdr64, e_phentsize, %hd, );
    PRINT_STC(p_ehdr64, e_phnum, %hd, );
    PRINT_STC(p_ehdr64, e_shentsize, %hd, );
    PRINT_STC(p_ehdr64, e_shnum, %hd, );
    PRINT_STC(p_ehdr64, e_shstrndx, %hd, );
    
    return 0;
}
