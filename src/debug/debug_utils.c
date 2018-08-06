#include <linux/elf.h>

#include "analy_debug.h"
#include "elf_analyzer.h"

Elf64_Xword
decode_uLEB128(Elf64_Addr p) {
    Elf64_Xword num = 0;
    int i = 0;
    do num += (*((Elf64_Byte*)p) & 0x7f) << ((i++) * 7); while ((*((Elf64_Byte*)p++) & 0x80) != 0);
    return num;
}

Elf64_Sxword
decode_sLEB128(Elf64_Addr p) {
    Elf64_Xword num = 0;
    int i = 0;
    while ((*((Elf64_Byte*)p) & 0x80) != 0) {
        num += (*((Elf64_Byte*)p) & 0x7f) << ((i) * 7);
        p++; i++;
    }
    num += (*((Elf64_Byte*)p) & 0x7f) << ((i) * 7);
    // signed expansion
    if ((*((Elf64_Byte*)p) & 0x40) != 0)
        num += -1 << ((i+1)*7);
    return num;
}
