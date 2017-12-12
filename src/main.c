#include <stdio.h>
#include <stdlib.h>
#include <linux/elf.h>
#include "elf_analyzer.h"

#define FREE_IF_EXIST(ptr) \
    if ((ptr) != NULL) free(ptr);

FILE *fp;
Elf64_Ehdr *p_ehdr64;
Elf64_Phdr *p_ptbl64;
Elf64_Shdr *p_stbl64;
Elf64_Shdr *p_shstr64;

int
load() {
    load_ehdr();
    load_ptbl();
    load_stbl();
    load_shstr();
    return 0;
}

int
release() {
    FREE_IF_EXIST(p_ehdr64);
    FREE_IF_EXIST(p_ptbl64);
    FREE_IF_EXIST(p_stbl64);
    return 0;
}

int
main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "No input file\n");
        return -1;
    }

    char *fname = argv[1];
    fp = fopen(fname, "rb");
    if (fp == NULL) {
        perror(argv[1]);
        return -1;
    }

    load();
    repl();
    release();

    fclose(fp);
    return 0;
}
