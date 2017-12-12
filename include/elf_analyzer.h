#ifndef ELF_ANALYZER_INCLUDED
#define ELF_ANALYZER_INCLUDED
#include <stdio.h>
#include <linux/elf.h>

extern FILE *fp;
extern Elf64_Ehdr *p_ehdr64;
extern Elf64_Phdr *p_ptbl64;
extern Elf64_Shdr *p_stbl64;
extern Elf64_Shdr *p_shstr64;

int load();
int repl();
int release();

int load_ehdr();

int load_ptbl();
int read_phdr(Elf64_Phdr *pp, int ndx);

int load_stbl();
int load_shstr();
int read_shdr(Elf64_Shdr *ps, int ndx);
int read_sname(char *name, const Elf64_Shdr *ps, int size);
int read_str(char *str, int ndx, int size);
#endif
