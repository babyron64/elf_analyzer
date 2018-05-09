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

/*** string table section ***/
int read_strtbl(char *str, const Elf64_Shdr *ps, Elf64_Half ndx, size_t size);

/*** string table section for section name **/
int load_shstr();
const Elf64_Shdr* get_shstr();
int read_shstr(char *str, Elf64_Half ndx, size_t size);

/*** symbol table section ***/
int read_symtbl(Elf64_Sym *psym, Elf64_Half ndx, const Elf64_Shdr *psh);
int print_syment(const Elf64_Sym *psym);

/*** rel table section ***/
int read_reltbl(Elf64_Rel *prel, Elf64_Half ndx, const Elf64_Shdr *psh);
int print_relent(const Elf64_Rel *prel);

/*** rela table section ***/
int read_relatbl(Elf64_Rela *prela, Elf64_Half ndx, const Elf64_Shdr *psh);
int print_relaent(const Elf64_Rela *prela);

/*** dynamic table section ***/
int read_dyntbl(Elf64_Dyn *pdyn, Elf64_Half ndx, const Elf64_Shdr *psh);
int print_dynent(const Elf64_Dyn *pdyn);
int print_dyn_list(const Elf64_Shdr *psh);
int get_d_tag(Elf64_Sxword d_tag, char* buf, size_t size);

#endif
