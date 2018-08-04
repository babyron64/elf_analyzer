#include <stdio.h>
#include <linux/elf.h>

#include "analy_sec.h"
#include "elf_analyzer.h"

int
read_strtbl(char *str, const Elf64_Shdr *ps, Elf64_Half ndx, size_t size) {
    if (ps->sh_type != SHT_STRTAB) {
        fprintf(stderr, "The section is not a string table\n");
        return -1;
    }

    Elf64_Off offset = ps->sh_offset;
    if (size + ndx > ps->sh_size) {
        read_elf(str, ps->sh_size - ndx, offset+ndx);
        str[ps->sh_size - ndx] = '\0';
    } else {
        read_elf(str, size, offset+ndx);
    }
    str[size-1] = '\0';
    return 0;
}
