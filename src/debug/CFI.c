#include <stdio.h>
#include <linux/elf.h>

#include "analy_sec.h"
#include "elf_analyzer.h"
#include "analy_debug.h"

CFI_Handle getCFIHandle(Elf64_Addr code) {
    CFI_Handle handle = { code, code };
    return handle;
}

#define CFI_HIGH2_MSK (0b11<<6)

void read_CFI(CFI_Handle *handle, CFI_Instruction *ins) {
    Elf64_Byte head = *(Elf64_Byte*)handle->current;
    Elf64_Byte op = (head & CFI_HIGH2_MSK) >> 6;
    handle->current += 1;

#define CFI_STORE_INS_ARGS_ULEB128(n) \
    ins->args.arg ## n = decode_uLEB128(handle->current); \
    SKIP_LEB128(handle->current);
#define CFI_STORE_INS_ARGS_SLEB128(n) \
    ins->args.arg ## n = (Elf64_Xword)decode_sLEB128(handle->current); \
    SKIP_LEB128(handle->current);
#define CFI_STORE_INS_ARGS_BLOCK(n) \
    ins->args.arg ## n = handle->current; \
    SKIP_BLOCK(handle->current);
#define CFI_STORE_INS_ARGS_BYTE(n) \
    ins->args.arg ## n = *(Elf64_Byte*)handle->current; \
    handle->current += 1;
#define CFI_STORE_INS_ARGS_HALF(n) \
    ins->args.arg ## n = *(Elf64_Half*)handle->current; \
    handle->current += 2;
#define CFI_STORE_INS_ARGS_WORD(n) \
    ins->args.arg ## n = *(Elf64_Word*)handle->current; \
    handle->current += 4;
#define CFI_STORE_INS_ARGS_XWORD(n) \
    ins->args.arg ## n = *(Elf64_Xword*)handle->current; \
    handle->current += 8;
#define CFI_STORE_INS_ARGS_ADDR(n) \
    ins->args.arg ## n = *(Elf64_Addr*)handle->current; \
    handle->current += 8;

    if (op == 0) {
        Elf64_Byte exop = head & ~CFI_HIGH2_MSK;
         if (exop == 0x0) {
            ins->op = DW_CFA_nop;
            return;
        } else if (exop == 0x1) {
            ins->op = DW_CFA_set_loc;
            CFI_STORE_INS_ARGS_ADDR(1);
            return;
        } else if (exop == 0x2) {
            ins->op = DW_CFA_advance_loc1;
            CFI_STORE_INS_ARGS_BYTE(1);
            return;
        } else if (exop == 0x3) {
            ins->op = DW_CFA_advance_loc2;
            CFI_STORE_INS_ARGS_HALF(1);
            return;
        } else if (exop == 0x4) {
            ins->op = DW_CFA_advance_loc4;
            CFI_STORE_INS_ARGS_WORD(1);
            return;
        } else if (exop == 0x5) {
            ins->op = DW_CFA_offset_extended;
            CFI_STORE_INS_ARGS_ULEB128(1);
            CFI_STORE_INS_ARGS_ULEB128(2);
            return;
        } else if (exop == 0x6) {
            ins->op = DW_CFA_restore_extended;
            CFI_STORE_INS_ARGS_ULEB128(1);
            return;
        } else if (exop == 0x7) {
            ins->op = DW_CFA_undefined;
            CFI_STORE_INS_ARGS_ULEB128(1);
            return;
        } else if (exop == 0x8) {
            ins->op = DW_CFA_same_value;
            CFI_STORE_INS_ARGS_ULEB128(1);
            return;
        } else if (exop == 0x9) {
            ins->op = DW_CFA_register;
            CFI_STORE_INS_ARGS_ULEB128(1);
            CFI_STORE_INS_ARGS_ULEB128(2);
            return;
        } else if (exop == 0xa) {
            ins->op = DW_CFA_remember_state;
            return;
        } else if (exop == 0xb) {
            ins->op = DW_CFA_restore_state;
            return;
        } else if (exop == 0xc) {
            ins->op = DW_CFA_def_cfa;
            CFI_STORE_INS_ARGS_ULEB128(1);
            CFI_STORE_INS_ARGS_ULEB128(2);
            return;
        } else if (exop == 0xd) {
            ins->op = DW_CFA_def_cfa_register;
            CFI_STORE_INS_ARGS_ULEB128(1);
            return;
        } else if (exop == 0xe) {
            ins->op = DW_CFA_def_cfa_offset;
            CFI_STORE_INS_ARGS_ULEB128(1);
            return;
        } else if (exop == 0x1c) {
            ins->op = DW_CFA_lo_user;
            return;
        } else if (exop == 0x3f) {
            ins->op = DW_CFA_hi_user;
            return;
        } else if (exop == 0xf) {
            ins->op = DW_CFA_def_cfa_expression;
            CFI_STORE_INS_ARGS_BLOCK(1);
            return;
        } else if (exop == 0x10) {
            ins->op = DW_CFA_expression;
            CFI_STORE_INS_ARGS_ULEB128(1);
            CFI_STORE_INS_ARGS_BLOCK(2);
            return;
        } else if (exop == 0x11) {
            ins->op = DW_CFA_offset_extended_sf;
            CFI_STORE_INS_ARGS_ULEB128(1);
            CFI_STORE_INS_ARGS_SLEB128(2);
            return;
        } else if (exop == 0x12) {
            ins->op = DW_CFA_def_cfa_sf;
            CFI_STORE_INS_ARGS_ULEB128(1);
            CFI_STORE_INS_ARGS_SLEB128(2);
            return;
        } else if (exop == 0x13) {
            ins->op = DW_CFA_def_cfa_offset_sf;
            CFI_STORE_INS_ARGS_SLEB128(1);
            return;
        } else if (exop == 0x14) {
            ins->op = DW_CFA_val_offset;
            CFI_STORE_INS_ARGS_ULEB128(1);
            CFI_STORE_INS_ARGS_ULEB128(2);
            return;
        } else if (exop == 0x15) {
            ins->op = DW_CFA_val_offset_sf;
            CFI_STORE_INS_ARGS_ULEB128(1);
            CFI_STORE_INS_ARGS_SLEB128(2);
            return;
        } else if (exop == 0x16) {
            ins->op = DW_CFA_val_expression;
            CFI_STORE_INS_ARGS_ULEB128(1);
            CFI_STORE_INS_ARGS_BLOCK(2);
            return;
        }
    } else if (op == 1) {
        ins->op = DW_CFA_advance_loc;

        ins->args.arg1 = head & ~CFI_HIGH2_MSK;

        return;
    } else if (op == 2) {
        ins->op = DW_CFA_offset;

        ins->args.arg1 = head & ~CFI_HIGH2_MSK;

        ins->args.arg2 = decode_uLEB128(handle->current);
        SKIP_LEB128(handle->current);

        return;
    } else if (op == 3) {
        ins->op = DW_CFA_restore;

        ins->args.arg1 = head & ~CFI_HIGH2_MSK;

        return;
    }

    ins->op = DW_CFA_error;
    ins->args.arg1 = op;
    ins->args.arg2 = head & ~CFI_HIGH2_MSK;
    return;
}

void print_CFI(CFI_Instruction *ins) {
    switch(ins->op) {
        case DW_CFA_error:
            printf("DW_CFA_error ");
            printf("%llxh ", ins->args.arg1);
            printf("%llxh ", ins->args.arg2);
            break;
        case DW_CFA_advance_loc:
            printf("DW_CFA_advance_loc ");
            printf("%llxh ", ins->args.arg1);
            break;
        case DW_CFA_offset:
            printf("DW_CFA_offset ");
            printf("%llxh ", ins->args.arg1);
            printf("%llxh ", ins->args.arg2);
            break;
        case DW_CFA_restore:
            printf("DW_CFA_restore ");
            printf("%llxh ", ins->args.arg1);
            break;
        case DW_CFA_nop:
            printf("DW_CFA_nop ");
            break;
        case DW_CFA_set_loc:
            printf("DW_CFA_set_loc ");
            printf("%llxh ", ins->args.arg1);
            break;
        case DW_CFA_advance_loc1:
            printf("DW_CFA_advance_loc1 ");
            printf("%llxh ", ins->args.arg1);
            break;
        case DW_CFA_advance_loc2:
            printf("DW_CFA_advance_loc2 ");
            printf("%llxh ", ins->args.arg1);
            break;
        case DW_CFA_advance_loc4:
            printf("DW_CFA_advance_loc4 ");
            printf("%llxh ", ins->args.arg1);
            break;
        case DW_CFA_offset_extended:
            printf("DW_CFA_offset_extended ");
            printf("%llxh ", ins->args.arg1);
            printf("%llxh ", ins->args.arg2);
            break;
        case DW_CFA_restore_extended:
            printf("DW_CFA_restore_extended ");
            printf("%llxh ", ins->args.arg1);
            break;
        case DW_CFA_undefined:
            printf("DW_CFA_undefined ");
            printf("%llxh ", ins->args.arg1);
            break;
        case DW_CFA_same_value:
            printf("DW_CFA_same_value ");
            printf("%llxh ", ins->args.arg1);
            break;
        case DW_CFA_register:
            printf("DW_CFA_register ");
            printf("%llxh ", ins->args.arg1);
            printf("%llxh ", ins->args.arg2);
            break;
        case DW_CFA_remember_state:
            printf("DW_CFA_remember_state ");
            break;
        case DW_CFA_restore_state:
            printf("DW_CFA_restore_state ");
            break;
        case DW_CFA_def_cfa:
            printf("DW_CFA_def_cfa ");
            printf("%llxh ", ins->args.arg1);
            printf("%llxh ", ins->args.arg2);
            break;
        case DW_CFA_def_cfa_register:
            printf("DW_CFA_def_cfa_register ");
            printf("%llxh ", ins->args.arg1);
            break;
        case DW_CFA_def_cfa_offset:
            printf("DW_CFA_def_cfa_offset ");
            printf("%llxh ", ins->args.arg1);
            break;
        case DW_CFA_lo_user:
            printf("DW_CFA_lo_user");
            break;
        case DW_CFA_hi_user:
            printf("DW_CFA_hi_user");
            break;
        case DW_CFA_def_cfa_expression:
            printf("DW_CFA_def_cfa_expression ");
            printf("%llxh ", ins->args.arg1);
            break;
        case DW_CFA_expression:
            printf("DW_CFA_expression ");
            printf("%llxh ", ins->args.arg1);
            printf("%llxh ", ins->args.arg2);
            break;
        case DW_CFA_offset_extended_sf:
            printf("DW_CFA_offset_extended_sf ");
            printf("%llxh ", ins->args.arg1);
            printf("%llxh ", ins->args.arg2);
            break;
        case DW_CFA_def_cfa_sf:
            printf("DW_CFA_def_cfa_sf ");
            printf("%llxh ", ins->args.arg1);
            printf("%llxh ", ins->args.arg2);
            break;
        case DW_CFA_def_cfa_offset_sf:
            printf("DW_CFA_def_cfa_offset_sf ");
            printf("%llxh ", ins->args.arg1);
            break;
        case DW_CFA_val_offset:
            printf("DW_CFA_val_offset ");
            printf("%llxh ", ins->args.arg1);
            printf("%llxh ", ins->args.arg2);
            break;
        case DW_CFA_val_offset_sf:
            printf("DW_CFA_val_offset_sf ");
            printf("%llxh ", ins->args.arg1);
            printf("%llxh ", ins->args.arg2);
            break;
        case DW_CFA_val_expression:
            printf("DW_CFA_val_expression ");
            printf("%llxh ", ins->args.arg1);
            printf("%llxh ", ins->args.arg2);
            break;
    }
    printf("\n");
}
