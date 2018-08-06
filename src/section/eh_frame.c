#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/elf.h>
#include <linux/types.h>

#include "analy_sec.h"
#include "analy_debug.h"
#include "elf_analyzer.h"

static int read_CIE_format(Elf64_Eh_Ent_CIE* pc, Elf64_Addr i);
static int read_FDE_format(Elf64_Eh_Ent_FDE* pf, Elf64_Addr i);
static int print_eh_ent_cie(const Elf64_Eh_Ent_CIE* pc);
static int print_eh_ent_fde(const Elf64_Eh_Ent_FDE* pf);
static int print_CFI_array(Elf64_Addr code, Elf64_Xword size);

typedef struct _EH_ENT_NODE {
    struct _EH_ENT_NODE* next;
    Elf64_Addr base;
    Elf64_Eh_Ent ent;
} EH_ENT_NODE;

static const Elf64_Shdr* p_shdr;
static void* p_eh_frame;
static EH_ENT_NODE* p_node;

int
load_eh_frame(const Elf64_Shdr* ps) {
    // preprocess for cache.
    if (ps == p_shdr) {
        return 0;
    } else if (p_eh_frame != NULL) {
        release_eh_frame();
    }

    char buf[16];
    read_sec_name(buf, ps, 16);
    if (strcmp(buf, ".eh_frame") != 0) {
        fprintf(stderr, "The section is not a eh_frame\n");
        return -1;
    }

    p_eh_frame = malloc(ps->sh_size);
    read_elf(p_eh_frame, ps->sh_size, ps->sh_offset);

    Elf64_Addr i = 0;
    Elf64_Addr j = 0;
    Elf64_Xword length = 0;
    p_node = (EH_ENT_NODE*)malloc(sizeof(EH_ENT_NODE));
    EH_ENT_NODE* current = p_node;
    current -> next = NULL;
    EH_ENT_NODE* prev = NULL;
    while (i < ps->sh_size) {
        i = j;
        current->base = (Elf64_Addr)p_eh_frame + i;

        length = *((Elf64_Word*)(p_eh_frame + j));
        j += 4;

        if (length == 0xffffffff) {
            length = *((Elf64_Xword*)(p_eh_frame + j));
            j += 8;
        }
        
        Elf64_Word cie_id = *((Elf64_Word*)(p_eh_frame + j));

        if (length == 0) {
            /** current->ent.type = cie_id == 0 ? CIE : FDE; */
            current->ent.type = CIE;
            break;
        }

        if (cie_id == 0) {
            read_CIE_format(&current->ent.eh_ent.cie, i);
            current->ent.type = CIE;
        } else {
            read_FDE_format(&current->ent.eh_ent.fde, i);
            current->ent.type = FDE;
        }

        j += length;
        prev = current;
        current = (EH_ENT_NODE*)malloc(sizeof(EH_ENT_NODE));
        prev->next = current;
        current->next = NULL;
    }

    p_shdr = ps;
    return 0;
}

int
release_eh_frame() {
    EH_ENT_NODE* current = p_node;
    EH_ENT_NODE* next = NULL;
    while (current) {
        next = current->next;
        FREE_IF_EXIST(current);
        current = next;
    } 
    return 0;
}

static int
read_CIE_format(Elf64_Eh_Ent_CIE* pc, Elf64_Addr i) {
    Elf64_Xword total_len = 0;
    Elf64_Addr base = i;
    pc->length = *((Elf64_Word*)(p_eh_frame + i));
    i += 4; total_len += 4;

    if (pc->length == 0xffffffff) {
        pc->ex_length = *((Elf64_Xword*)(p_eh_frame + i));
        i += 8; total_len += 8;
        total_len += pc->ex_length;
    } else {
        total_len += pc->length;
    }
    
    pc->cie_id = *((Elf64_Word*)(p_eh_frame + i));
    i += 4;

    pc->version = *((Elf64_Byte*)(p_eh_frame + i));
    i += 1;

    pc->aug = (Elf64_Addr)(p_eh_frame + i);
    while (((char*)p_eh_frame)[i] != '\0') i++;
    i += 1; 

    if (((char*)pc->aug)[0] != '\0') {
        if (strstr(((char*)pc->aug), "eh") != NULL) {
            pc->eh_data = *((Elf64_Xword*)(p_eh_frame + i));
            i += 8;
        }
    }

    pc->code_align = (Elf64_Addr)(p_eh_frame + i);
    while ((((Elf64_Byte*)p_eh_frame)[i] & 0x80) != 0) i++;
    i++;

    pc->data_align = (Elf64_Addr)(p_eh_frame + i);
    while ((((Elf64_Byte*)p_eh_frame)[i] & 0x80) != 0) i++;
    i++;

    pc->return_reg = (Elf64_Addr)(p_eh_frame + i);
    while ((((Elf64_Byte*)p_eh_frame)[i] & 0x80) != 0) i++;
    i++;

    pc->aug_data = (Elf64_Addr)(p_eh_frame + i);

    char *aug = (char*)pc->aug;
    if (aug && aug[0] == 'z') {
        while (*aug) {
            if (*aug == 'z') {
                pc->aug_z = (Elf64_Addr)(p_eh_frame + i);
                while ((((Elf64_Byte*)p_eh_frame)[i++] & 0x80) != 0);
            } else if (*aug == 'L') {
                pc->aug_L = ((Elf64_Byte*)p_eh_frame)[i++];
            } else if (*aug == 'P') {
                pc->aug_P = ((Elf64_Byte*)p_eh_frame)[i++];
            } else if (*aug == 'R') {
                pc->aug_R = ((Elf64_Byte*)p_eh_frame)[i++];
            }
            aug++;
        }
    }

    pc->init = (Elf64_Addr)(p_eh_frame + i);
    pc->init_len = total_len - (i - base);
    
    return 0;
}

static int
read_FDE_format(Elf64_Eh_Ent_FDE* pf, Elf64_Addr i) {
    Elf64_Xword total_len = 0;
    Elf64_Addr base = i;
    Elf64_Addr j = 0;
    pf->length = *((Elf64_Word*)(p_eh_frame + i));
    i += 4; j += 4;

    if (pf->length == 0xffffffff) {
        pf->ex_length = *((Elf64_Xword*)(p_eh_frame + i));
        i += 8; j += 8;
        total_len = j + pf->ex_length;
    } else {
        total_len = j + pf->length;
    }
    
    pf->cie_pointer = *((Elf64_Word*)(p_eh_frame + i));
    i += 4;

    Elf64_Addr cie_base = ((Elf64_Addr)p_eh_frame) + base + j - pf->cie_pointer;
    EH_ENT_NODE* current = p_node;
    pf->cie_idx = 0;
    while (current != NULL) {
        if (current->base == cie_base) {
            pf->cie = &current->ent.eh_ent.cie;
            break;
        }
        current = current->next;
        pf->cie_idx++;
    }

    if (pf->cie == NULL) {
        fprintf(stderr, "The associated CIE is not found\n");
        return -1;
    }

    if (pf->cie->aug_R) {
        if (((pf->cie->aug_R & 0x0f) == EH_PE_uleb128) ||
                ((pf->cie->aug_R & 0x0f) == EH_PE_sleb128)) {
            pf->pc_begin = (Elf64_Addr)(p_eh_frame + i);
            while ((((Elf64_Byte*)p_eh_frame)[i++] & 0x80) != 0);
            pf->pc_range = (Elf64_Addr)(p_eh_frame + i);
            while ((((Elf64_Byte*)p_eh_frame)[i++] & 0x80) != 0);
        } else if (((pf->cie->aug_R & 0x0f) == EH_PE_udata2) ||
                ((pf->cie->aug_R & 0x0f) == EH_PE_sdata2)) {
            pf->pc_begin = *(Elf64_Half*)(p_eh_frame + i);
            i += 2;
            pf->pc_range = *(Elf64_Half*)(p_eh_frame + i);
            i += 2; 
        } else if (((pf->cie->aug_R & 0x0f) == EH_PE_udata4) ||
                ((pf->cie->aug_R & 0x0f) == EH_PE_sdata4)) {
            pf->pc_begin = *(Elf64_Word*)(p_eh_frame + i);
            i += 4;
            pf->pc_range = *(Elf64_Word*)(p_eh_frame + i);
            i += 4; 
        } else if (((pf->cie->aug_R & 0x0f) == EH_PE_udata8) ||
                ((pf->cie->aug_R & 0x0f) == EH_PE_sdata8) ||
                ((pf->cie->aug_R & 0x0f) == EH_PE_signed)) {
            pf->pc_begin = *(Elf64_Xword*)(p_eh_frame + i);
            i += 8;
            pf->pc_range = *(Elf64_Xword*)(p_eh_frame + i);
            i += 8; 
        } else {
            pf->pc_begin = *(Elf64_Xword*)(p_eh_frame + i);
            i += 8;
            pf->pc_range = *(Elf64_Xword*)(p_eh_frame + i);
            i += 8; 
        }
    }


    if (pf->cie->aug_z) {
        pf->aug_z = (Elf64_Addr)(p_eh_frame + i);
        while ((((Elf64_Byte*)p_eh_frame)[i++] & 0x80) != 0);

        pf->aug_data = (Elf64_Addr)(p_eh_frame + i);
        i += decode_uLEB128(pf->aug_z);
    }

    pf->cfi = (Elf64_Addr)(p_eh_frame + i);
    pf->cfi_len = total_len - (i - base);

    return 0;
}

Elf64_Eh_Ent*
get_eh_frame_ent(const Elf64_Shdr *ps, Elf64_Half ndx) {
    char buf[16];
    read_sec_name(buf, ps, 16);
    if (strcmp(buf, ".eh_frame") != 0) {
        fprintf(stderr, "The section is not a eh_frame\n");
        return NULL;
    }

    load_eh_frame(ps);

    EH_ENT_NODE* current = p_node;
    for (int i=0; i<ndx; i++) {
        if (!current)
           return NULL; 
        current = current->next;
    }
    if (!current)
        return NULL;

    // current is allocated by malloc, so current->ent is not located in stack memory.
    return &(current->ent);
}

int print_eh_ent(const Elf64_Eh_Ent *peh) {
    if (!peh->eh_ent.info.length) {
        printf("--- CIE_END ---\n");
        return 0;
    }

    if (peh->type == CIE) 
        return print_eh_ent_cie(&peh->eh_ent.cie);
    else
        return print_eh_ent_fde(&peh->eh_ent.fde);
}

int print_eh_list(const Elf64_Shdr *psh) {
    load_eh_frame(psh);

    int i = 0;
    EH_ENT_NODE* current = p_node;
    while (current) {
        if (current->ent.eh_ent.info.length)
            printf("%d:\t%s\n", i, current->ent.type == CIE ? "CIE" : "FDE");
        else 
            printf("%d:\t%s\n", i, "END");
        current = current->next; i++;
    }

    return 0;
}

static int
print_eh_ent_cie(const Elf64_Eh_Ent_CIE* pc) {
    printf("--- EH_FRAME ENTRY (CIE) ---\n");
    PRINT_STC(pc, length, %u,);
    if (pc->ex_length != 0)
        PRINT_STC(pc, ex_length, %llu,);
    PRINT_STC(pc, cie_id, %x, h);
    PRINT_STC(pc, version, %u,);
    PRINT_STC_WITH_NAME(pc, aug, %llx, h, (char*)pc->aug);

    if (strstr((char*)pc->aug, "eh") != NULL)
        printf("eh_data:\t%llxh\n", pc->eh_data);

    printf("code_align:\t%llxh\n", decode_uLEB128(pc->code_align));
    Elf64_Xword data_align;
    if ((data_align = decode_sLEB128(pc->data_align)) & (1U << 8))
        printf("data_align:\t-%llxh\n", -data_align);
    else 
        printf("data_align:\t%llxh\n", data_align);
    printf("return_reg:\t%llxh\n", decode_uLEB128(pc->return_reg));

    if (pc->aug_z)
        printf("aug_z:\t%llu\n", decode_uLEB128(pc->aug_z));
    if (pc->aug_L)
        printf("aug_L:\t%xh\n", pc->aug_L);
    if (pc->aug_R)
        printf("aug_R:\t%xh\n", pc->aug_R);
    if (pc->aug_P)
        printf("aug_P:\t%xh\n", pc->aug_P);

    /** PRINT_STC(pc, init, %llx, h); */
    printf("init:\n");
    print_CFI_array(pc->init, pc->init_len);

    return 0;
}

static int
print_eh_ent_fde(const Elf64_Eh_Ent_FDE* pf) {
    printf("--- EH_FRAME ENTRY (FDE) ---\n");
    PRINT_STC(pf, length, %u,);
    if (pf->ex_length != 0)
        PRINT_STC(pf, ex_length, %llu,);
    printf("parent_cie:\t%llu (%xh)\n", pf->cie_idx, pf->cie_pointer);

    if (pf->cie->aug_R) {
        Elf64_Sxword s_pc_begin;
        Elf64_Sxword s_pc_range;
        switch (pf->cie->aug_R & 0x0f) {
            case EH_PE_uleb128:
                printf("pc_begin:\t%llxh\n", decode_uLEB128(pf->pc_begin));
                printf("pc_range:\t%llxh\n", decode_uLEB128(pf->pc_range));
                break;
            case EH_PE_sleb128:
                s_pc_begin = decode_sLEB128(pf->pc_begin);
                s_pc_range = decode_sLEB128(pf->pc_range);
                goto EH_PE_SIGNED_ENCODE;
            case EH_PE_signed:
                s_pc_begin = (Elf64_Sxword)pf->pc_begin;
                s_pc_range = (Elf64_Sxword)pf->pc_range;
                goto EH_PE_SIGNED_ENCODE;
            case EH_PE_sdata2:
                s_pc_begin = (Elf64_SHalf)pf->pc_begin;
                s_pc_range = (Elf64_SHalf)pf->pc_range;
                goto EH_PE_SIGNED_ENCODE;
            case EH_PE_sdata4:
                s_pc_begin = (Elf64_Sword)pf->pc_begin;
                s_pc_range = (Elf64_Sword)pf->pc_range;
                goto EH_PE_SIGNED_ENCODE;
            case EH_PE_sdata8:
                s_pc_begin = (Elf64_Sxword)pf->pc_begin;
                s_pc_range = (Elf64_Sxword)pf->pc_range;
                goto EH_PE_SIGNED_ENCODE;
            EH_PE_SIGNED_ENCODE:
                if (s_pc_begin < 0)
                    printf("pc_begin:\t-%llxh\n", -s_pc_begin);
                else
                    printf("pc_begin:\t%llxh\n", s_pc_begin);
                if (s_pc_range < 0)
                    printf("pc_range:\t-%llxh\n", -s_pc_range);
                else
                    printf("pc_range:\t%llxh\n", s_pc_range);
                break;
            case EH_PE_udata2:
            case EH_PE_udata4:
            case EH_PE_udata8:
            default:
                printf("pc_begin:\t%llxh\n", pf->pc_begin);
                printf("pc_range:\t%llxh\n", pf->pc_range);
                break;
        }
    } else {
        PRINT_STC(pf, pc_begin, %llx, h);
        PRINT_STC(pf, pc_range, %llx, h);
    }

    if (pf->cie != NULL) {
        Elf64_Eh_Ent_CIE* pc = pf->cie;
        if (pc->aug_z) {
            printf("aug_z:\t%llu\n", decode_uLEB128(pf->aug_z));
            int i = 0;
            const char* p = (const char*)pc->aug;
            while (*p != '\0') {
                if (*p == 'L') {
                    printf("aug_data_L:\t%xh\n", *(Elf64_Byte*)(pf->aug_data + i));
                    i += 1;
                }
                p++;
            }
        }
    }

    /** PRINT_STC(pf, cfi, %llx, h); */
    printf("cfi:\n");
    print_CFI_array(pf->cfi, pf->cfi_len);
    return 0;
}

static int
print_CFI_array(Elf64_Addr code, Elf64_Xword size) {
    CFI_Handle handle = getCFIHandle(code);
    CFI_Instruction ins;
    Elf64_Xword i = 0;
    while (handle.current < handle.base + size) {
        read_CFI(&handle, &ins);
        printf("\t%llu:\t", i++);
        print_CFI(&ins);
    }
    return 0;
}
