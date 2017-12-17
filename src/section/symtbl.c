#include <stdio.h>
#include <linux/elf.h>

#include "analy_sec.h"
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
print_syment(const Elf64_Sym *psym) {
    printf("--- SYMBOL TABLE ENTRY ---\n");
    PRINT_STC(psym, st_name, %d, );
    PRINT_STC(psym, st_info, %hhx, h);
    PRINT_STC(psym, st_other, %hhx, h);
    PRINT_STC(psym, st_shndx, %hd, );
    PRINT_STC(psym, st_value, %llx, h);
    PRINT_STC(psym, st_size, %lld, );

    return 0;
}
