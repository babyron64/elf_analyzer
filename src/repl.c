#include <stdio.h>
#include <linux/elf.h>
#include "elf_analyzer.h"

extern Elf64_Shdr *p_shstr64;

int print_info();

int
repl() {
    print_info();
    return 0;
}

int
print_info() {
    printf("entry point: %llx\n", p_ehdr64->e_entry);
    char buf[16];
    read_sname(buf, p_shstr64, 16);
    printf("string section name: %s\n",buf);
    return 0;
}
