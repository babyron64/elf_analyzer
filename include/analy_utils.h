#ifndef ANALY_UTILS_INCLUDED
#define ANALY_UTILS_INCLUDED

int print_sep();

typedef enum {
    HEX,
    BIN,
    ASC,
    NA_DUMP_TYPE
} DUMP_TYPE;

int hex_dump(size_t size, Elf64_Addr offset);
int bin_dump(size_t size, Elf64_Addr offset);
int asc_dump(size_t size, Elf64_Addr offset);

#endif
