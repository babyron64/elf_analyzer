#ifndef ANALY_SEG_INCLUDED
#define ANALY_SEG_INCLUDED

#include <linux/elf.h>
#include "analy_utils.h"

/*** program header table **/
int load_ptbl();
int release_ptbl();

const Elf64_Phdr* get_phdr(Elf64_Half ndx);
int print_phdr(const Elf64_Phdr *pp);
int print_seg_dump(const Elf64_Phdr* pp, BASE_TYPE type);

#endif
