#include <stdio.h>
#include <stdlib.h>
#include <linux/elf.h>

#include "analy_utils.h"
#include "elf_analyzer.h"

static int hex_byte2char(char *buf, const unsigned char byte) ;
static char hex_half2char(const unsigned char half);
static int bin_byte2char(char *buf, const unsigned char byte) ;
static char bin_bit2char(const unsigned char bit);
static char asc_byte2char(const unsigned char byte);

int
hex_dump(size_t size, Elf64_Addr offset) {
    if (size == 0) {
        printf("No content exists\n");
        return 0;
    }
    printf("(hex) %lubyte\n", size); print_sep();
    unsigned char *bins = (unsigned char *)load_elf(size, offset);
    unsigned char *pb = bins;
    /**
     * hex=** ** ** \n
     ***/
    char str[8];
    for (int i=1; i<=size; i++, pb++) {
        hex_byte2char(str, *pb); 
        str[2] = ' ';
        str[3] = '\0';
        printf("%s", str);
        if (!(i & 0b111)) {
            if (i & 0b11111)
                printf("   ");
            else
                printf("\n");
        }
    }
    printf("\n");

    FREE_IF_EXIST(bins);
    return 0;
} 

static int
hex_byte2char(char *buf, const unsigned char byte) {
    char low = hex_half2char(byte & 0x0f);
    char high = hex_half2char(byte >> 4);
    buf[0] = high;
    buf[1] = low; 
    return 0;
}

static char
hex_half2char(const unsigned char half) {
    if (half < 10)
        return (char)(half+48);
    else
        return (char)(half+87);
}

int
bin_dump(size_t size, Elf64_Addr offset) {
    if (size == 0) {
        printf("No content exists\n");
        return 0;
    }
    printf("(bin) %lubyte\n", size); print_sep();
    unsigned char *bins = (unsigned char *)load_elf(size, offset);
    unsigned char *pb = bins;
    /**
     * bin=******** ******** ******** \n
     **/
    char str[16];
    for (int i=1; i<=size; i++, pb++) {
        bin_byte2char(str, *pb);
        str[8] = ' ';
        str[9] = '\0';
        printf("%s", str);
        if (!(i & 0b111)) {
            if (i & 0b1111)
                printf("   ");
            else
                printf("\n");
        }
    }
    printf("\n");

    FREE_IF_EXIST(bins);
    return 0;
}

static int
bin_byte2char(char *buf, const unsigned char byte) {
    /***
     * 0b********
     * i=01234567
     ***/
    char bit;
    for (int i=0; i<8; i++) {
        bit = (byte & (0xff >> i)) >> (7 - i);
        buf[i] = bin_bit2char(bit);
    }
    return 0;
}

static char
bin_bit2char(const unsigned char bit) {
    return (char)(bit+48);
}

int
asc_dump(size_t size, Elf64_Addr offset) {
    if (size == 0) {
        printf("No content exists\n");
        return 0;
    }
    printf("(ascii) %lubyte\n", size); print_sep();
    unsigned char *bins = (unsigned char *)load_elf(size, offset);
    unsigned char *pb = bins;
    /**
     * asc=****\n
     ***/
    for (int i=1; i<=size; i++, pb++) {
        printf("%c", asc_byte2char(*pb));
        if (!(i & 0b111)) {
            if (i & 0b111111)
                printf("   ");
            else
                printf("\n");
        }
    }
    printf("\n");

    FREE_IF_EXIST(bins);
    return 0;
}

static char
asc_byte2char(const unsigned char byte) {
    if (33 <= byte && byte <= 126)
        return (char)byte;
    else
        return '.';
}

int
print_sep() {
    int num = 32;
    for (int i=0; i<num; i++)
        putchar('-');
    putchar('\n');
    return 0;
}

