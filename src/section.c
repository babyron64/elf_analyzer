#include <stdio.h>
#include <stdlib.h>
#include <linux/elf.h>

#include "analy_elf.h"
#include "analy_sec.h"
#include "elf_analyzer.h"

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
    const Elf64_Ehdr *p_ehdr64 = get_ehdr();
    if (ndx < 0 || ndx >= p_ehdr64->e_shnum)
        return NULL;
    return &p_stbl64[ndx];
}

int
print_shdr(const Elf64_Shdr *ps) {
    char buf[16];
    printf("--- SECTION HEADER ENTRY ---\n");
    read_sec_name(buf, ps, 16);
    PRINT_STC_WITH_NAME(ps, sh_name, %x, h, buf);
    PRINT_STC(ps, sh_type, %x, h);
    PRINT_STC(ps, sh_flags, %llx, h);
    PRINT_STC(ps, sh_addr, %llx, h);
    PRINT_STC(ps, sh_offset, %llx, h);
    PRINT_STC(ps, sh_size, %lld, );
    PRINT_STC(ps, sh_link, %x, h);
    PRINT_STC(ps, sh_info, %x, h);
    PRINT_STC(ps, sh_addralign, %lld, );
    PRINT_STC(ps, sh_entsize, %lld, );

    return 0;
}

int
print_sec_list() {
    const Elf64_Ehdr *p_ehdr64 = get_ehdr();
    int num = p_ehdr64->e_shnum;
    const Elf64_Shdr *ps;
    char name[16];
    printf("index\tname\n");
    for(int i=0; i<num; i++) {
        ps = get_shdr(i);
        read_sec_name(name, ps, 16);
        printf("%d\t%s\n", i, name);
    }
    return 0;
}

int
print_sec_dump(const Elf64_Shdr* ps, DUMP_TYPE type) {
    Elf64_Off offset = ps->sh_offset;
    Elf64_Xword size = ps->sh_size;
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
        default:
            fprintf(stderr, "Illegal dump type\n");
            break;
    }
    return 0;
}


int
read_sec_name(char *name, const Elf64_Shdr *ps, int size) {
    Elf64_Word str_ndx = ps->sh_name;
    read_shstr(name, str_ndx, size);
    return 0;
}
