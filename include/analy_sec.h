#ifndef ANALY_SEC_INCLUDED
#define ANALY_SEC_INCLUDED

#include <linux/elf.h>
#include "analy_utils.h"
#include "elf_analyzer.h"

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
// Visit https://www.airs.com/blog/archives/460 for more details about PE (pointer encoding) setting.

// An absolute pointer.
// The size is determined by whether this is a 32-bit or 64-bit address space, and will be 32 or 64 bits.
#define EH_PE_absptr     0x00 
// The value is omitted.
#define EH_PE_omit       0xff
// The value is an unsigned LEB128.
#define EH_PE_uleb128    0x01
// The value is stored as unsigned data with the specified number of bytes.
#define EH_PE_udata2     0x02
#define EH_PE_udata4     0x03
#define EH_PE_udata8     0x04
// A signed number.
// The size is determined by whether this is a 32-bit or 64-bit address space.
// I don’t think this ever appears in a CIE or FDE in practice.
#define EH_PE_signed     0x08
// A signed LEB128. Not used in practice.
#define EH_PE_sleb128    0x09
// The value is stored as signed data with the specified number of bytes.
// Not used in practice.
#define EH_PE_sdata2     0x0a
#define EH_PE_sdata4     0x0b
#define EH_PE_sdata8     0x0c

// Value is PC relative.
#define EH_PE_pcrel      0x10
// Value is text relative.
#define EH_PE_textrel    0x20
// Value is data relative.
#define EH_PE_datarel    0x30
// Value is relative to start of function.
#define EH_PE_funcrel    0x40
// Value is aligned: padding bytes are inserted as required to make value be naturally aligned.
#define EH_PE_aligned    0x50
// This is actually the address of the real value.
#define EH_PE_indirect   0x80

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
    Elf64_Addr aug_data;
    Elf64_Addr return_reg;
    Elf64_Addr init;

    Elf64_Word init_len;

    Elf64_Addr aug_z;
    Elf64_Byte aug_P;
    Elf64_Byte aug_R;
    Elf64_Byte aug_L;
} Elf64_Eh_Ent_CIE;
typedef struct _Elf64_Eh_Ent_FDE {
    // If length is 0, the CIE is considered as a terminator.
    Elf64_Word length;
    Elf64_Xword ex_length;
    Elf64_Word cie_pointer;
    Elf64_Addr pc_begin;
    Elf64_Addr pc_range;
    Elf64_Addr aug_data;
    Elf64_Addr cfi;

    Elf64_Eh_Ent_CIE* cie;
    Elf64_Xword cie_idx;
    Elf64_Word cfi_len;

    Elf64_Addr aug_z;
    Elf64_Xword aug_L;
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
