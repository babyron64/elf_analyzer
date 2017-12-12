#include <stdio.h>
#include <stdlib.h>
#include <linux/elf.h>
#include "elf_analyzer.h"

extern FILE *fp;
extern Elf64_Ehdr *p_ehdr64;
extern Elf64_Phdr *p_ptbl64;

int
load_ptbl() {
    if (p_ehdr64->e_phoff == 0) {
        p_ptbl64 = NULL;
        return 0;
    }
    size_t ptb_size = p_ehdr64->e_phentsize * p_ehdr64->e_phnum;
    p_ptbl64 = (Elf64_Phdr *)malloc(ptb_size);
    fseek(fp, p_ehdr64->e_phoff, SEEK_SET);
    fread(p_ptbl64, ptb_size, 1, fp);
    return 0;
}
    
int
read_phdr(Elf64_Phdr *pp, int ndx) {
    pp = &p_ptbl64[ndx];
    return 0;
}
