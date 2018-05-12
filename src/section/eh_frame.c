#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/elf.h>
#include <linux/types.h>

#include "analy_sec.h"
#include "elf_analyzer.h"

static int read_CIE_format(Elf64_Eh_Ent_CIE* pc, Elf64_Addr i);
static int read_FDE_format(Elf64_Eh_Ent_FDE* pf, Elf64_Addr i);
static Elf64_Xword decode_uLEB128(Elf64_Addr p);
static Elf64_Sxword decode_sLEB128(Elf64_Addr p);
static int print_eh_ent_cie(const Elf64_Eh_Ent_CIE* pc);
static int print_eh_ent_fde(const Elf64_Eh_Ent_FDE* pf);

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
    if (ps == p_eh_frame) {
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
            current->ent.type = cie_id == 0 ? CIE : FDE;
            break;
        }

        if (cie_id == 0) {
            read_CIE_format(&current->ent.eh_ent.cie, i);
            current->ent.type = CIE;
        } else {
            read_FDE_format(&current->ent.eh_ent.fde, i);
            current->ent.type = FDE;
        }

        i += length;
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
    pc->length = *((Elf64_Word*)(p_eh_frame + i));
    i += 4;

    if (pc->length == 0xffffffff) {
        pc->ex_length = *((Elf64_Xword*)(p_eh_frame + i));
        i += 8;
    }
    
    pc->cie_id = *((Elf64_Word*)(p_eh_frame + i));
    i += 4;

    pc->version = *((Elf64_Word*)(p_eh_frame + i));
    i += 4;

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
    while ((((Elf_Byte*)p_eh_frame)[i] & 0x80) != 0) i++;
    i++;

    pc->data_align = (Elf64_Addr)(p_eh_frame + i);
    while ((((Elf_Byte*)p_eh_frame)[i] & 0x80) != 0) i++;
    i++;

    pc->return_addr = (Elf64_Addr)(p_eh_frame + i);
    while ((((Elf_Byte*)p_eh_frame)[i] & 0x80) != 0) i++;
    i++;

    if (((char*)pc->aug)[0] == 'z') {
        pc->aug_len = (Elf64_Addr)(p_eh_frame + i);
        while ((*((Elf_Byte*)(p_eh_frame + i)) & 0x80) != 0) i++;
        i++;

        pc->aug_data = (Elf64_Addr)(p_eh_frame + i);
        i += decode_uLEB128(pc->aug_len);
    }

    pc->init = (Elf64_Addr)(p_eh_frame + i);
    
    return 0;
}

static int
read_FDE_format(Elf64_Eh_Ent_FDE* pf, Elf64_Addr i) {
    Elf64_Addr base = i;
    pf->length = *((Elf64_Word*)(p_eh_frame + i));
    i += 4;

    if (pf->length == 0xffffffff) {
        pf->ex_length = *((Elf64_Xword*)(p_eh_frame + i));
        i += 8;
    }
    
    pf->cie_pointer = *((Elf64_Word*)(p_eh_frame + i));
    i += 4;

    pf->pc_begin = (Elf64_Addr)(p_eh_frame + i);
    i += 8;

    pf->pc_range = (Elf64_Addr)(p_eh_frame + i);
    i += 8; 

    Elf64_Addr cie_base = base - pf->cie_pointer;
    EH_ENT_NODE* current = p_node;
    while (current != NULL) {
        if (current->base == cie_base) {
            pf->cie = &current->ent.eh_ent.cie;
            break;
        }
        current = current->next;
    }

    if (pf->cie == NULL) {
        fprintf(stderr, "The associated CIE is not found\n");
    } else {
        if (((char*)pf->cie->aug)[0] == 'z') {
            pf->aug_len = (Elf64_Addr)(p_eh_frame + i);
            while ((((Elf_Byte*)p_eh_frame)[i] & 0x80) != 0) i++;
            i++;

            pf->aug_data = (Elf64_Addr)(p_eh_frame + i);
            i += decode_uLEB128(pf->aug_len);
        }
    }

    pf->cfi = (Elf64_Addr)(p_eh_frame + i);
    
    return 0;
}

Elf64_Eh_Ent*
get_eh_frame_ent(const Elf64_Shdr *ps, Elf64_Half ndx, size_t size) {
    char buf[16];
    read_sec_name(buf, ps, 16);
    if (strcmp(buf, ".eh_frame") != 0) {
        fprintf(stderr, "The section is not a eh_frame\n");
        return NULL;
    }

    EH_ENT_NODE* current = p_node;
    for (int i=0; i<ndx; i++) {
        if (current)
           return NULL; 
        current = current->next;
    }

    // current is allocated by malloc, so current->ent is not located in stack memory.
    return &(current->ent);
}

static Elf64_Xword
decode_uLEB128(Elf64_Addr p) {
    Elf64_Xword num = 0;
    int i = 0;
    do num += (*((Elf_Byte*)p) & 0x7f) << ((i++) * 7); while ((*((Elf_Byte*)p++) & 0x80) != 0);
    return num;
}

static Elf64_Sxword
decode_sLEB128(Elf64_Addr p) {
    Elf64_Xword num = 0;
    int i = 0;
    while ((*((Elf_Byte*)p) & 0x80) != 0) {
        num += (*((Elf_Byte*)p) & 0x7f) << ((i) * 7);
        p++; i++;
    }
    num += (*((Elf_Byte*)p) & 0x7f) << ((i) * 7);
    // signed expansion
    if ((*((Elf_Byte*)p) & 0x40) != 0)
        num += -1 << ((i+1)*7);
    return num;
}

int print_eh_ent(const Elf64_Eh_Ent *peh) {
    if (peh->type == CIE) 
        return print_eh_ent_cie(&peh->eh_ent.cie);
    else
        return print_eh_ent_fde(&peh->eh_ent.fde);
}

int print_eh_list(const Elf64_Shdr *psh) {
    load_eh_frame(psh);

    int i = 0;
    EH_ENT_NODE* current = p_node;
    while (current != NULL) {
        printf("%d:\t%s\n", i, current->ent.type == CIE ? "CIE" : "FDE");
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
    printf("data_align:\t%llxh\n", decode_sLEB128(pc->data_align));
    printf("return_addr:\t%llxh\n", decode_uLEB128(pc->return_addr));

    if (((char*)pc->aug)[0] == 'z') {
        printf("aug_len:\t%llu\n", decode_uLEB128(pc->aug_len));
        int i = 0;
        const char* p = (const char*)pc->aug;
        while (*p != '\0') {
            if (*p == 'L') {
                printf("aug_data_L:\t%xh\n", *(Elf_Byte*)(pc->aug_data + i));
                i += 1;
            } else if (*p == 'P') {
                printf("aug_data_P:\t%xh\n", *(Elf64_Half*)(pc->aug_data + i));
                i += 2;
            } else if (*p == 'R') {
                printf("aug_data_R:\t%xh\n", *(Elf_Byte*)(pc->aug_data + i));
                i += 1;
            }
            p++;
        }
    }

    PRINT_STC(pc, init, %llx, h);

    return 0;
}

static int
print_eh_ent_fde(const Elf64_Eh_Ent_FDE* pf) {
    printf("--- EH_FRAME ENTRY (FDE) ---\n");
    PRINT_STC(pf, length, %u,);
    if (pf->ex_length != 0)
        PRINT_STC(pf, ex_length, %llu,);
    PRINT_STC(pf, cie_pointer, %x, h);

    PRINT_STC(pf, pc_begin, %llx, h);
    PRINT_STC(pf, pc_range, %llx, h);

    if (pf->cie != NULL) {
        Elf64_Eh_Ent_CIE* pc = pf->cie;
        if (((char*)pc->aug)[0] == 'z') {
            printf("aug_len:\t%llu\n", decode_uLEB128(pf->aug_len));
            int i = 0;
            const char* p = (const char*)pc->aug;
            while (*p != '\0') {
                if (*p == 'L') {
                    printf("aug_data_L:\t%xh\n", *(Elf_Byte*)(pf->aug_data + i));
                    i += 1;
                }
                p++;
            }
        }
    }

    PRINT_STC(pf, cfi, %llx, h);
    return 0;
}
