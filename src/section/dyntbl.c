#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
    char buf[128];
    get_d_tag(pdyn->d_tag, buf, 128);
    PRINT_STC_WITH_NAME(pdyn, d_tag, %lld, d, buf);
    // Pass d_val instead of d_un, which is to be passed if possible, because d_un is a union and can't be displayed by format string %llx, etc..
    PRINT_STC(pdyn, d_un.d_val, %llx, h);

    return 0;
}

int
print_dyn_list(const Elf64_Shdr *psh) {
    Elf64_Dyn *pdyn = (Elf64_Dyn *)malloc(psh->sh_entsize);
    
    int tbl_len = psh->sh_size / psh->sh_entsize;
    char buf[128];
    for (int i=0; i<tbl_len; i++) {
        if (read_dyntbl(pdyn, i, psh) == -1) {
            continue;
        }
        get_d_tag(pdyn->d_tag, buf, 128);
        printf("%d\t%s\n", i, buf);
    }

    FREE_IF_EXIST(pdyn);
    return 0;
}

int
get_d_tag(Elf64_Sxword d_tag, char* buf, size_t size) {
    char* sni_name = "(error) unknown DT type";
    const Elf64_Sxword sni_value = d_tag;
#include "d_tag.sni"
    strncpy(buf, sni_name, size);
    buf[size-1] = '\0';
    return 0;
}
