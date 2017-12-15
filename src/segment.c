#include <stdio.h>
#include <stdlib.h>
#include <linux/elf.h>

#include "elf_analyzer.h"
#include "analy_seg.h"

static Elf64_Phdr *p_ptbl64 = NULL;

int
load_ptbl() {
    const Elf64_Ehdr *p_ehdr64 = get_ehdr();

    if (p_ehdr64->e_phoff == 0) {
        p_ptbl64 = NULL;
        return 0;
    }

    size_t ptb_size = p_ehdr64->e_phentsize * p_ehdr64->e_phnum;
    p_ptbl64 = (Elf64_Phdr *)load_elf(ptb_size, p_ehdr64->e_phoff);
    return 0;
}

int
release_ptbl() {
    FREE_IF_EXIST(p_ptbl64);
    return 0;
}
    
const Elf64_Phdr*
get_phdr(Elf64_Half ndx) {
    return &p_ptbl64[ndx];
}

int
print_phdr(const Elf64_Phdr *pp) {
    PRINT_STC(pp, p_type, %x);
    PRINT_STC(pp, p_flags, %x);
    PRINT_STC(pp, p_offset, %llx);
    PRINT_STC(pp, p_vaddr, %llx);
    PRINT_STC(pp, p_paddr, %llx);
    PRINT_STC(pp, p_filesz, %llx);
    PRINT_STC(pp, p_memsz, %llx);
    PRINT_STC(pp, p_align, %llx);
    
    return 0;
}
