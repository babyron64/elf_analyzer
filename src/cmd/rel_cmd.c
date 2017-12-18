#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/elf.h>

#include "ehdr_cmd.h"
#include "analy_elf.h"
#include "analy_sec.h"
#include "analy_cmd.h"
#include "elf_analyzer.h"

static int eval_rel_read(int cmdc, int ix, char cmds[][MAX_CMD_LEN]);

int
eval_rel(int cmdc, int ix, char cmds[][MAX_CMD_LEN]) {
    if (cmdc == 0) {
        eval_error("Unknown command");
        return -1;
    }

    char *cmd = cmds[ix];

    if (strcmp(cmd, "read") == 0)
        return CMD_CALL(eval_rel_read, cmdc, ix, cmds);

    eval_error("Unknown command");
    return -1;
}

static int
eval_rel_read(int cmdc, int ix, char cmds[][MAX_CMD_LEN]) {
    int ndx = 0;
    int str_ndx = 0;
    if (cmdc == 0) {
        eval_error("Too few argument");
        return -1;
    }

NDX: ;
    char *cmd = cmds[ix];
    if (strcmp(cmd, "0") == 0) goto STR_NDX;
    ndx = atoi(cmd);
    if (ndx == 0) {
        eval_error("Illegal argument");
        return -1;
    }

STR_NDX: ;
    if (cmdc == 1) goto SHOW;
    cmd = cmds[ix+1];
    if (strcmp(cmd, "0") == 0) goto SHOW;
    str_ndx = atoi(cmd);
    if (str_ndx == 0) {
        eval_error("Illegal argument");
        return -1;
    }

SHOW: ;
    const Elf64_Shdr *ps = get_shdr(ndx);
    if (ps == NULL) {
        eval_error("No such an entry");
        return -1;
    }
    Elf64_Rel *prel = (Elf64_Rel *)malloc(ps->sh_entsize);
    if (read_reltbl(prel, str_ndx, ps) == -1) {
        FREE_IF_EXIST(prel);
        return -1;
    }

    print_relent(prel);
    FREE_IF_EXIST(prel);
    return 0;
}
