#include <stdio.h>
#include <stdlib.h>
#include <linux/elf.h>

#include "elf_analyzer.h"
#include "analy_ctrl.h"

static FILE* fp;

int
elf_open(char *fname) {
    fp = fopen(fname, "rb");
    if (fp == NULL) {
        perror(fname);
        return -1;
    }
    return 0;
}

int
close_elf() {
    fclose(fp);
    return 0;
}

void*
load_elf(size_t size, Elf64_Addr offset) {
    void *ptr = malloc(size);
    fseek(fp, offset, SEEK_SET);
    fread(ptr, size, 1, fp);
    return ptr;
}

int
read_elf(void *ptr, size_t size, Elf64_Addr offset) {
    fseek(fp, offset, SEEK_SET);
    fread(ptr, size, 1, fp);
    return 0;
}
