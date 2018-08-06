#ifndef ANALY_DEBUG_INCLUDED
#define ANALY_DEBUG_INCLUDED

#define SKIP_LEB128(addr) while (*(Elf64_Byte*)(addr++) & 0x80U);
#define SKIP_BLOCK(addr) do { \
    Elf64_Xword len = decode_uLEB128(addr); \
    SKIP_LEB128(addr); \
    addr += len; } while(0);

Elf64_Xword decode_uLEB128(Elf64_Addr p);
Elf64_Sxword decode_sLEB128(Elf64_Addr p);

typedef enum _CFI_Op {
    DW_CFA_error = -1,
    DW_CFA_advance_loc = 1,
    DW_CFA_offset,
    DW_CFA_restore,
    DW_CFA_nop,
    DW_CFA_set_loc,
    DW_CFA_advance_loc1,
    DW_CFA_advance_loc2,
    DW_CFA_advance_loc4,
    DW_CFA_offset_extended,
    DW_CFA_restore_extended,
    DW_CFA_undefined,
    DW_CFA_same_value,
    DW_CFA_register,
    DW_CFA_remember_state,
    DW_CFA_restore_state,
    DW_CFA_def_cfa,
    DW_CFA_def_cfa_register,
    DW_CFA_def_cfa_offset,
    DW_CFA_lo_user,
    DW_CFA_hi_user,
    // Dwarf varsion 3
    DW_CFA_def_cfa_expression,
    DW_CFA_expression,
    DW_CFA_offset_extended_sf,
    DW_CFA_def_cfa_sf,
    DW_CFA_def_cfa_offset_sf,
    DW_CFA_val_offset,
    DW_CFA_val_offset_sf,
    DW_CFA_val_expression,
} CFI_Op;

typedef struct _CFI_Arguments {
    Elf64_Xword arg1;
    Elf64_Xword arg2;
    Elf64_Xword arg3;
} CFI_Arguments;

typedef struct _CFI_Instruction {
    CFI_Op op;
    CFI_Arguments args;
} CFI_Instruction;

typedef struct _CFI_Handle {
    Elf64_Addr current;
    Elf64_Addr base;
} CFI_Handle;

CFI_Handle getCFIHandle(Elf64_Addr code);

void read_CFI(CFI_Handle *handle, CFI_Instruction *ins);

void print_CFI(CFI_Instruction *ins);

#endif // ANALY_DEBUG_INCLUDED
