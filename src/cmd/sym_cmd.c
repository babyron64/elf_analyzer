#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/elf.h>

#include "ehdr_cmd.h"
#include "analy_sec.h"
#include "analy_elf.h"
#include "analy_cmd.h"
#include "elf_analyzer.h"

static int eval_sym_show(int cmdc, int ix, char cmds[][MAX_CMD_LEN]);

int
eval_sym(int cmdc, int ix, char cmds[][MAX_CMD_LEN]) {
    if (cmdc == 0)
        return CMD_CALL(eval_sym_show, cmdc, ix, cmds);

    char *cmd = cmds[ix];
    
    if (strcmp(cmd, "show") == 0)
        return CMD_CALL(eval_sym_show, cmdc, ix, cmds);

    eval_error("Unknown command");
    return -1;
}

static int
eval_sym_show(int cmdc, int ix, char cmds[][MAX_CMD_LEN]) {
    int ndx = 0;
    if (cmdc == 0) {
        eval_error("Unknown command");
        return -1;
    }
    if (cmdc != 1) {
        eval_error("Too many arguments");
        return -1;
    }
    char *cmd = cmds[ix];
    if (strcmp(cmd, "0") == 0) goto SHOW;
    ndx = atoi(cmd);
    if (ndx == 0) {
        eval_error("Illegal argument");
        return -1;
    }

SHOW: ;
    const Elf64_Shdr *ps = get_shdr(ndx);
    if (ps == NULL) {
        eval_error("No such an entry");
        return -1;
    }
    Elf64_Sym sym;
    if (read_symtbl(&sym, ndx, ps) == -1)
        return -1;
    print_syment(&sym);

    return 0;
}
