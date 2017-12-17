#ifndef ANALY_CTRL_INCLUDED
#define ANALY_CTRL_INCLUDED

#define MAX_NUMERIC 40000
#define MAX_CMD_LEN 8
#define MAX_TOK_NUM 8


int elf_open(char *fname);
int close_elf();

typedef enum {
    QUIT = MAX_NUMERIC,
    EHDR,
    SHDR,
    PHDR,
    SEG,
    SEC,
    LIST,
    DUMP,
    B, H
} Tok;

int repl();
int eval(char cmds[][MAX_CMD_LEN]);

#endif
