#include <stdio.h>
#include <string.h>
#include <linux/elf.h>

#include "analy_sec.h"
#include "analy_elf.h"
#include "elf_analyzer.h"

int
read_symtbl(Elf64_Sym *psym, Elf64_Half ndx, const Elf64_Shdr *psh) {
    if (psh->sh_type != SHT_SYMTAB) {
        fprintf(stderr, "The section is not a symbol table\n");
        return -1;
    }
    Elf64_Off sh_offset = psh->sh_offset;
    Elf64_Off sym_offset = psh->sh_entsize * ndx;
    read_elf(psym, psh->sh_entsize, sh_offset+sym_offset);
    return 0;
}

int
print_syment(const Elf64_Shdr* psh, int ndx) {
    Elf64_Sym sym;
    if (read_symtbl(&sym, ndx, psh) == -1)
        return -1;

    printf("--- SYMBOL TABLE ENTRY ---\n");
    char buf[256];
    read_strtbl(buf, get_shdr(psh->sh_link), sym.st_name, 256);
    if (buf[0] == '\0')
        strcpy(buf,"No name");
    PRINT_STC_WITH_NAME(&sym, st_name, %d,, buf);
    PRINT_STC(&sym, st_info, %hhx, h);
    PRINT_STC(&sym, st_other, %hhx, h);
    PRINT_STC(&sym, st_shndx, %hd, );
    PRINT_STC(&sym, st_value, %llx, h);
    PRINT_STC(&sym, st_size, %lld, );

    return 0;
}

int
print_sym_list(const Elf64_Shdr* psh) {
    if (psh->sh_type != SHT_SYMTAB) {
        fprintf(stderr, "The section is not a symbol table\n");
        return -1;
    }
    Elf64_Sym sym;

    int tbl_len = psh->sh_size / psh->sh_entsize;
    char buf[256];
    for (int i=0; i<tbl_len; i++) {
        if (read_symtbl(&sym, i, psh) == -1)
            continue;

        read_strtbl(buf, get_shdr(psh->sh_link), sym.st_name, 256);
        if (buf[0] == '\0')
            strcpy(buf,"No name");
        printf("%d\t%s\n", i, buf);
    }
    return 0;
}
