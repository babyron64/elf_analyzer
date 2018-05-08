#include <stdio.h>
#include <linux/elf.h>

#include "analy_sec.h"
#include "elf_analyzer.h"

int
read_dyntbl(Elf64_Dyn *pdyn, Elf64_Half ndx, const Elf64_Shdr *psh) {
    if (psh->sh_type != SHT_DYNAMIC) {
        fprintf(stderr, "The section is not for dynamic linking\n");
        return -1;
    }
    Elf64_Off sh_offset = psh->sh_offset;
    Elf64_Off dyn_offset = psh->sh_entsize * ndx;
    read_elf(pdyn, psh->sh_entsize, sh_offset+dyn_offset);
    return 0;
}

int
print_dynent(const Elf64_Dyn *pdyn) {
    printf("--- DYNAMIC LINKAGE INFO TABLE ENTRY ---\n");
    PRINT_STC(pdyn, d_tag, %llx, h);
    PRINT_STC(pdyn, d_un, %llx, h);

    return 0;
}
