#include <stdio.h>
#include <stdlib.h>
#include <linux/elf.h>

#include "analy_elf.h"
#include "analy_seg.h"
#include "elf_analyzer.h"

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
    const Elf64_Ehdr *p_ehdr64 = get_ehdr();
    if (ndx < 0 || ndx >= p_ehdr64->e_phnum)
        return NULL;
    return &p_ptbl64[ndx];
}

int
print_phdr(const Elf64_Phdr *pp) {
    printf("--- PROGRAM HEADER ENTRY ---\n");
    PRINT_STC(pp, p_type, %x, h);
    PRINT_STC(pp, p_flags, %x, h);
    PRINT_STC(pp, p_offset, %llx, h);
    PRINT_STC(pp, p_vaddr, %llx, h);
    PRINT_STC(pp, p_paddr, %llx, h);
    PRINT_STC(pp, p_filesz, %lld, );
    PRINT_STC(pp, p_memsz, %lld, );
    PRINT_STC(pp, p_align, %lld, );
    
    return 0;
}

int
print_seg_dump(const Elf64_Phdr* pp, DUMP_TYPE type) {
    Elf64_Off offset = pp->p_offset;
    Elf64_Xword size = pp->p_filesz;
    switch (type) {
        case HEX:
            hex_dump(size, offset);
            break;
        case BIN:
            bin_dump(size, offset);
            break;
        case ASC:
            asc_dump(size, offset);
            break;
    }
    return 0;
}
