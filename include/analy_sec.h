#ifndef ANALY_SEC_INCLUDED
#define ANALY_SEC_INCLUDED

#include <linux/elf.h>
#include "analy_utils.h"

/*** section header table **/
int load_stbl();
int release_stbl();

const Elf64_Shdr* get_shdr(Elf64_Half ndx);
int print_shdr(const Elf64_Shdr *ps);
int print_sec_list();

int read_sec_name(char *name, const Elf64_Shdr *ps, int size);
int print_sec_dump(const Elf64_Shdr* ps, DUMP_TYPE type);

/*** string table section **/
int load_shstr();
const Elf64_Shdr* get_shstr();
int read_shstr(char *str, Elf64_Half ndx, size_t size);

#endif
