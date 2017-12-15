#ifndef ANALY_ELF_INCLUDED
#define ANALY_ELF_INCLUDED

#include <linux/elf.h>

int load_ehdr();
int release_ehdr();

const Elf64_Ehdr* get_ehdr();
int print_ehdr();

#endif
