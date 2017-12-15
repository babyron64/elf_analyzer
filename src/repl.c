#include <stdio.h>
#include <linux/elf.h>

#include "elf_analyzer.h"

int print_info();

int
repl() {
    print_info();
    return 0;
}

int
print_info() {
    const Elf64_Ehdr *p_ehdr64 = get_ehdr();
    const Elf64_Shdr *p_shstr64 = get_shstr();

    printf("entry point: %llx\n", p_ehdr64->e_entry);
    char buf[16];
    read_sec_name(buf, p_shstr64, 16);
    printf("string section name: %s\n",buf);
    return 0;
}
