#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/elf.h>

#include "analy_ctrl.h"
#include "elf_analyzer.h"

#define MAX_TOK_NUM 4

static int loop();
static int read_toks(Tok *toks, char *inputs);
static Tok get_tok(const char *cmd);
static int print_info();

int
repl() {
    loop();
    return 0;
}

static int
loop() {
    char cmd[128];
    Tok toks[MAX_TOK_NUM];
    int res;

    while (1) {
        printf("(elf_analyzer) ");
        scanf("%s", cmd);
        read_toks(toks, cmd);
        res = eval(toks);
        if (res == 1)
            break;
        if (res == -1)
            fprintf(stderr, "command execution failure");
    }

    return 0;
}

static int
read_toks(Tok *toks, char *inputs) {
    char *p = strtok(inputs, " ");
    Tok tok;

    int i = 0;
    while (1) {
        if (p == NULL || i == MAX_TOK_NUM)
            break;
        tok = get_tok(p);
        if (tok == -1)
            return -1;
        toks[i++] = tok;
        p = strtok(NULL, " ");
    }

    return 0;
}

static Tok
get_tok(const char *cmd) {
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

static int
print_info() {
    const Elf64_Ehdr *p_ehdr64 = get_ehdr();
    const Elf64_Shdr *p_shstr64 = get_shstr();

    printf("entry point: %llx\n", p_ehdr64->e_entry);
    char buf[16];
    read_sec_name(buf, p_shstr64, 16);
    printf("string section name: %s\n",buf);
    print_ehdr();
    return 0;
}
