#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <linux/elf.h>

#include "analy_ctrl.h"
#include "elf_analyzer.h"

static int read_cmds(Tok *toks, char cmds[][MAX_CMD_LEN]);
static Tok get_tok(const char *cmd);
static bool is_digit(Tok tok);
static int eval_error(char *mes);
static int eval_ehdr(Tok toks[MAX_TOK_NUM]);
static int eval_phdr(Tok toks[MAX_TOK_NUM]);
static int eval_shdr(Tok toks[MAX_TOK_NUM]);
static int eval_seg(Tok toks[MAX_TOK_NUM]);
static int eval_sec(Tok toks[MAX_TOK_NUM]);

static int
read_cmds(Tok *toks, char cmds[][MAX_CMD_LEN]) {
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
    else if (0 > num) {
        eval_error("Negative number is not allowed");
        return -1;
    }
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
    else if(strcmp(cmd, "list") == 0 || strcmp(cmd, "ls") == 0)
        return LIST;
    else if(strcmp(cmd, "dump") == 0)
        return DUMP;
    else if(strcmp(cmd, "b") == 0)
        return B;
    else if(strcmp(cmd, "h") == 0)
        return H;
    return -1;
}

static bool
is_digit(Tok tok) {
    if (0 <= tok && tok < MAX_NUMERIC)
        return true;
    return false;
}

int
eval(char cmds[][MAX_CMD_LEN]) {
    Tok toks[MAX_TOK_NUM] = {0};
    int res;
    res = read_cmds(toks, cmds);
    if (res == -1) {
        eval_error("unknown command");
        goto EVAL_FIN;
    }

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

EVAL_FIN:
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
    if (! is_digit(toks[0]))
        return -1;
    print_phdr(get_phdr(toks[0]));
    return 0;
}

static int
eval_shdr(Tok toks[MAX_TOK_NUM]) {
    if (toks[1] != 0) {
        eval_error("shdr: Too many arguments");
        return -1;
    }
    if (! is_digit(toks[0]))
        return -1;
    print_shdr(get_shdr(toks[0]));
    return 0;
}

static int
eval_seg(Tok toks[MAX_TOK_NUM]) {
    if (toks[1] != 0) {
        eval_error("seg: Too many arguments");
        return -1;
    }

    if (is_digit(toks[0])) {
        const Elf64_Phdr *pp = get_phdr(toks[0]);
        if (pp == NULL) {
            eval_error("seg: No such an entry");
            return 0;
        }
        print_phdr(pp);
        return 0;
    }
    return -1;
}

static int
eval_sec(Tok toks[MAX_TOK_NUM]) {
    if (toks[0] == LIST) {
        print_sec_list();
        return 0;
    }
    else if (toks[0] == DUMP) {
        if (! is_digit(toks[1])) {
            eval_error("sec: Invalid index\n");
            return -1;
        }
        const Elf64_Shdr *ps = get_shdr(toks[1]);
        if (ps == NULL) {
            eval_error("sec: No such an entry");
            return 0;
        }
        if (toks[2] == B)
            print_sec_dump(ps, BIN);
        else
            print_sec_dump(ps, HEX);
        return 0;
    }
    else if (is_digit(toks[0])) {
        const Elf64_Shdr *ps = get_shdr(toks[0]);
        if (ps == NULL) {
            eval_error("sec: No such an entry");
            return 0;
        }
        print_shdr(ps);
        return 0;
    }

    return -1;
}
