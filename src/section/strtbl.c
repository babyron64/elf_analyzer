#include <stdio.h>
#include <linux/elf.h>

#include "analy_sec.h"
#include "elf_analyzer.h"

int
read_strtbl(char *str, const Elf64_Shdr *ps, Elf64_Half ndx, size_t size) {
    // TODO
    // check size+ndx is not larger than p_shstr64->sh_size
    // I haven't implemented error handling and,
    // to avoid using error, I don't implement it now.
    if (ps->sh_type != SHT_STRTAB) {
        fprintf(stderr, "The section is not a string table\n");
        return -1;
    }
    Elf64_Off offset = ps->sh_offset;
    read_elf(str, size, offset+ndx); 
    str[size-1] = "\0";
    return 0;
}
