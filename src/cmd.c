#include <stdio.h>

#include <linux/elf.h>
#include "analy_ctrl.h"
#include "elf_analyzer.h"

static int eval_error(char *mes);
static int eval_ehdr(Tok toks[]);
static int eval_phdr(Tok toks[]);
static int eval_shdr(Tok toks[]);
static int eval_seg(Tok toks[]);
static int eval_sec(Tok toks[]);

int eval(Tok toks[]) {
    int res;
    switch (toks[0]) {
        case QUIT:
            res = 1;
        case EHDR:
            res = eval_ehdr(toks++);
            break;
        case PHDR:
            res = eval_phdr(toks++);
            break;
        case SHDR:
            res = eval_shdr(toks++);
            break;
        case SEG:
            res = eval_seg(toks++);
            break;
        case SEC:
            res = eval_sec(toks++);
            break;
        default:
            eval_error("unknown command");
            res = -1;
    }
    return res;
}

static int
eval_error(char *mes) {
    fprintf(stderr, "%s\n", mes);
    return 0;
}

static int
eval_ehdr(Tok toks[]) {
    if (toks[0] != 0) {
        eval_error("ehdr: Too many arguments");
        return -1;
    }
    print_ehdr();
    return 0;
}

static int
eval_phdr(Tok toks[]) {
    if (toks[1] != 0) {
        eval_error("ehdr: Too many arguments");
        return -1;
    }
    print_phdr(get_phdr(toks[0]));
    return 0;
}

static int
eval_shdr(Tok toks[]) {
    if (toks[1] != 0) {
        eval_error("ehdr: Too many arguments");
        return -1;
    }
    print_shdr(get_shdr(toks[0]));
    return 0;
}

static int
eval_seg(Tok toks[]) {
    if (toks[1] != 0) {
        eval_error("ehdr: Too many arguments");
        return -1;
    }
    return -1;
}

static int
eval_sec(Tok toks[]) {
    if (toks[1] != 0) {
        eval_error("ehdr: Too many arguments");
        return -1;
    }
    return -1;
}
