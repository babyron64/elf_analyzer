#include <stdio.h>

#include "elf_analyzer.h"
#include "analy_sec.h"

static const Elf64_Shdr *p_shstr64;

int
load_shstr() {
    const Elf64_Ehdr *p_ehdr64 = get_ehdr();

    Elf64_Half ndx = p_ehdr64->e_shstrndx;
    if (ndx == SHN_UNDEF) {
        p_shstr64 = NULL;
        return 0;
    }
    p_shstr64 = get_shdr(ndx);
    return 0;
}

const Elf64_Shdr*
get_shstr() {
    return p_shstr64;
}

int
read_shstr(char *str, Elf64_Half ndx, size_t size) {
    // TODO
    // check size+ndx is not larger than p_shstr64->sh_size
    // I haven't implemented error handling and,
    // to avoid using error, I don't implement it now.
    Elf64_Off p_sstr = p_shstr64->sh_offset;
    read_elf(str, size, p_sstr+ndx); 
    return 0;
}
