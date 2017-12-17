#include <stdio.h>
#include <linux/elf.h>

#include "analy_sec.h"
#include "elf_analyzer.h"

int
read_relatbl(Elf64_Rela *prela, Elf64_Half ndx, const Elf64_Shdr *psh) {
    if (psh->sh_type != SHT_RELA) {
        fprintf(stderr, "The section is not a relocation with addend table\n");
        return -1;
    }
    Elf64_Off sh_offset = psh->sh_offset;
    Elf64_Off rela_offset = psh->sh_entsize * ndx;
    read_elf(prela, psh->sh_entsize, sh_offset+rela_offset);
    return 0;
}

int
print_relaent(const Elf64_Rela *prela) {
    printf("--- RELOCATON with ADDEND TABLE ENTRY ---\n");
    PRINT_STC(prela, r_offset, %llx, h);
    PRINT_STC(prela, r_info, %llx, h);
    PRINT_STC(prela, r_addend, %lld, );

    return 0;
}
