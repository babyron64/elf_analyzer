#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/elf.h>

#include "analy_ctrl.h"
#include "elf_analyzer.h"

static int read_cmds(Tok *toks, char cmds[][MAX_TOK_NUM]);
static Tok get_tok(const char *cmd);
static int eval_error(char *mes);
static int eval_ehdr(Tok toks[MAX_TOK_NUM]);
static int eval_phdr(Tok toks[MAX_TOK_NUM]);
static int eval_shdr(Tok toks[MAX_TOK_NUM]);
static int eval_seg(Tok toks[MAX_TOK_NUM]);
static int eval_sec(Tok toks[MAX_TOK_NUM]);

static int
read_cmds(Tok *toks, char cmds[][MAX_TOK_NUM]) {
    Tok tok;
    int i = 0;
    while (i < MAX_TOK_NUM) {
        tok = get_tok(cmds[i]);
        if (tok == -1)
            return -1;
        toks[i++] = tok;
    }

    return 0;
}

static Tok
get_tok(const char *cmd) {
    if (cmd[0] == '\0')
        return 0;
    int num = atoi(cmd);
    if (0 < num && num < MAX_NUMERIC)
        return num;
    else if (strcmp(cmd, "0") == 0)
        return 0;
    else if (strcmp(cmd, "quit") == 0)
        return QUIT;
    else if (strcmp(cmd, "ehdr") == 0)
        return EHDR;
    else if (strcmp(cmd, "phdr") == 0)
        return PHDR;
    else if (strcmp(cmd, "shdr") == 0)
        return SHDR;
    else if (strcmp(cmd, "seg") == 0)
        return SEG;
    else if (strcmp(cmd, "sec") == 0)
        return SEC;
    return -1;
}

int
eval(char cmds[][MAX_TOK_NUM]) {
    Tok toks[MAX_TOK_NUM] = {0};
    int res;
    read_cmds(toks, cmds);
    switch (toks[0]) {
        case QUIT:
            res = 1;
            break;
        case EHDR:
            res = eval_ehdr(&toks[1]);
            break;
        case PHDR:
            res = eval_phdr(&toks[1]);
            break;
        case SHDR:
            res = eval_shdr(&toks[1]);
            break;
        case SEG:
            res = eval_seg(&toks[1]);
            break;
        case SEC:
            res = eval_sec(&toks[1]);
            break;
        default:
            eval_error("unknown command");
            res = -1;
            break;
    }
    if (res == -1)
        fprintf(stderr, "command execution failure: %u\n", toks[0]);
    return res;
}

static int
eval_error(char *mes) {
    fprintf(stderr, "%s\n", mes);
    return 0;
}

static int
eval_ehdr(Tok toks[MAX_TOK_NUM]) {
    if (toks[0] != 0) {
        eval_error("ehdr: Too many arguments");
        return -1;
    }
    print_ehdr();
    return 0;
}

static int
eval_phdr(Tok toks[MAX_TOK_NUM]) {
    if (toks[1] != 0) {
        eval_error("phdr: Too many arguments");
        return -1;
    }
    print_phdr(get_phdr(toks[0]));
    return 0;
}

static int
eval_shdr(Tok toks[MAX_TOK_NUM]) {
    if (toks[1] != 0) {
        eval_error("shdr: Too many arguments");
        return -1;
    }
    print_shdr(get_shdr(toks[0]));
    return 0;
}

static int
eval_seg(Tok toks[MAX_TOK_NUM]) {
    if (toks[1] != 0) {
        eval_error("seg: Too many arguments");
        return -1;
    }
    return -1;
}

static int
eval_sec(Tok toks[MAX_TOK_NUM]) {
    if (toks[1] != 0) {
        eval_error("sec: Too many arguments");
        return -1;
    }
    return -1;
}
