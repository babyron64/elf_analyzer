#include <stdio.h>
#include <stdlib.h>
#include <linux/elf.h>

#include "elf_analyzer.h"
#include "analy_sec.h"

static Elf64_Shdr *p_stbl64 = NULL;

int
load_stbl() {
    const Elf64_Ehdr *p_ehdr64 = get_ehdr();

    if (p_ehdr64->e_shoff == 0) {
        p_stbl64 = NULL;
        return 0;
    }

    size_t stb_size = p_ehdr64->e_shentsize * p_ehdr64->e_shnum;
    p_stbl64 = (Elf64_Shdr *)load_elf(stb_size, p_ehdr64->e_shoff);  
    return 0;
}

int
release_stbl() {
    FREE_IF_EXIST(p_stbl64);
    return 0;
}

const Elf64_Shdr*
get_shdr(Elf64_Half ndx) {
    return &p_stbl64[ndx];
}

int
print_shdr(const Elf64_Shdr *ps) {
    PRINT_STC(ps, sh_name, %x);
    PRINT_STC(ps, sh_type, %x);
    PRINT_STC(ps, sh_flags, %llx);
    PRINT_STC(ps, sh_addr, %llx);
    PRINT_STC(ps, sh_offset, %llx);
    PRINT_STC(ps, sh_size, %llx);
    PRINT_STC(ps, sh_link, %x);
    PRINT_STC(ps, sh_info, %x);
    PRINT_STC(ps, sh_addralign, %llx);
    PRINT_STC(ps, sh_entsize, %llx);

    return 0;
}

int
read_sec_name(char *name, const Elf64_Shdr *ps, int size) {
    Elf64_Word str_ndx = ps->sh_name;
    read_shstr(name, str_ndx, size);
    return 0;
}
