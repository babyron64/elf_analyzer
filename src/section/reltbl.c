#include <stdio.h>
#include <linux/elf.h>

#include "analy_sec.h"
#include "elf_analyzer.h"

int
read_reltbl(Elf64_Rel *prel, Elf64_Half ndx, const Elf64_Shdr *psh) {
    if (psh->sh_type != SHT_REL) {
        fprintf(stderr, "The section is not a relocation without addend table\n");
        return -1;
    }
    Elf64_Off sh_offset = psh->sh_offset;
    Elf64_Off rel_offset = psh->sh_entsize * ndx;
    read_elf(prel, psh->sh_entsize, sh_offset+rel_offset);
    return 0;
}

int
print_relent(const Elf64_Rel *prel) {
    printf("--- RELOCATON without ADDEND TABLE ENTRY ---\n");
    PRINT_STC(prel, r_offset, %llx, h);
    PRINT_STC(prel, r_info, %llx, h);
    {
        printf("\tr_sym:\t%lld\n", ELF64_R_SYM(prel->r_info));

        int sni_value;
        char *sni_name;

        sni_value = ELF64_R_TYPE(prel->r_info);
#include "st_bind.sni"
        printf("\tr_type:\t%s\n", sni_name);
    }

    return 0;
}
