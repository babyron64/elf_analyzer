#ifndef ANALY_SEC_INCLUDED
#define ANALY_SEC_INCLUDED

#include <linux/elf.h>
#include "analy_utils.h"

int release_sec();

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
int print_syment(const Elf64_Shdr *psh, int ndx);
int print_sym_list(const Elf64_Shdr* psh);

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

/*** eh_frame section ***/
typedef struct _Elf64_Eh_Ent_CIE {
    // If length is 0, the CIE is considered as a terminator.
    Elf64_Word length;
    Elf64_Xword ex_length;
    Elf64_Word cie_id;
    Elf64_Word version;
    Elf64_Addr aug;
    Elf64_Xword eh_data;
    Elf64_Addr code_align; 
    Elf64_Addr data_align; 
    Elf64_Addr aug_len; 
    Elf64_Addr aug_data;
    Elf64_Addr return_addr;
    Elf64_Addr init;
} Elf64_Eh_Ent_CIE;
typedef struct _Elf64_Eh_Ent_FDE {
    // If length is 0, the CIE is considered as a terminator.
    Elf64_Word length;
    Elf64_Xword ex_length;
    Elf64_Word cie_pointer;
    Elf64_Addr pc_begin;
    Elf64_Addr pc_range;
    Elf64_Addr aug_len;
    Elf64_Addr aug_data;
    Elf64_Addr cfi;
    Elf64_Eh_Ent_CIE* cie;
} Elf64_Eh_Ent_FDE;
typedef struct _Elf64_Eh_Ent_Info {
    // If length is 0, the CIE is considered as a terminator.
    Elf64_Word length;
    Elf64_Xword ex_length;
    Elf64_Word cie_id;
} Elf64_Eh_Ent_Info;


typedef enum _Elf_Eh_Ent_Type {
    CIE,
    FDE
} Elf_Eh_Ent_Type;
typedef struct _Elf64_Eh_Ent {
    union {
        Elf64_Eh_Ent_CIE cie;
        Elf64_Eh_Ent_FDE fde;
        Elf64_Eh_Ent_Info info;
    } eh_ent;
    Elf_Eh_Ent_Type type;
} Elf64_Eh_Ent;

int load_eh_frame(const Elf64_Shdr* ps);
int release_eh_frame();
Elf64_Eh_Ent* get_eh_frame_ent(const Elf64_Shdr *ps, Elf64_Half ndx);
int print_eh_ent(const Elf64_Eh_Ent *peh);
int print_eh_list(const Elf64_Shdr *psh);

#endif
