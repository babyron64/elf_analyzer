#ifndef ANALY_CTRL_INCLUDED
#define ANALY_CTRL_INCLUDED

#define MAX_NUMERIC 40000

int elf_open(char *fname);
int close_elf();

typedef enum {
    QUIT = MAX_NUMERIC,
    EHDR,
    SHDR,
    PHDR,
    SEG,
    SEC
} Tok;

int repl();
int eval(Tok toks[]);

#endif
