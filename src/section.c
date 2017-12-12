#include <stdio.h>
#include <stdlib.h>
#include <linux/elf.h>
#include "elf_analyzer.h"

extern FILE *fp;
extern Elf64_Ehdr *p_ehdr64;
extern Elf64_Shdr *p_stbl64;
extern Elf64_Shdr *p_shstr64;

int
load_stbl() {
    if (p_ehdr64->e_shoff == 0) {
        p_stbl64 = NULL;
        return 0;
    }
    size_t stb_size = p_ehdr64->e_shentsize * p_ehdr64->e_shnum;
    p_stbl64 = (Elf64_Shdr *)malloc(stb_size);
    fseek(fp, p_ehdr64->e_shoff, SEEK_SET);
    fread(p_stbl64, stb_size, 1, fp);
    return 0;
}

int
load_shstr() {
    Elf64_Half ndx = p_ehdr64->e_shstrndx;
    if (ndx == SHN_UNDEF) {
        p_shstr64 = NULL;
        return 0;
    }
    p_shstr64 = (Elf64_Shdr *)malloc(p_ehdr64->e_shentsize);
    read_shdr(p_shstr64, ndx);
    return 0;
}

int
read_shdr(Elf64_Shdr *ps, int ndx) {
    ps = &p_stbl64[ndx];
    return 0;
}

int
read_sname(char *name, const Elf64_Shdr *ps, int size) {
    Elf64_Word str_ndx = ps->sh_name;
    read_str(name, str_ndx, size);
    return 0;
}

int
read_str(char *str, int ndx, int size) {
    // TODO
    // check size+ndx is not larger than p_shstr64->sh_size
    // I haven't implemented error handling and,
    // to avoid using error, I don't implement it now.
    Elf64_Off p_sstr = p_shstr64->sh_offset;
    fseek(fp, p_sstr+ndx, SEEK_SET);
    fread(str, size, 1, fp);
    return 0;
}


