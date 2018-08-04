#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/elf.h>

#include "utils_cmd.h"
#include "analy_eval.h"
#include "analy_elf.h"
#include "analy_sec.h"
#include "analy_cmd.h"
#include "elf_analyzer.h"

static int eval_rel_show(char **cmds);

int
eval_rel(char **cmds) {
    if (is_last_cmd(cmds)) {
        eval_error("Unknown command");
        return -1;
    }

    char *cmd = cmds[0];
    cmds++;
    if (IS_TOK(cmd, show))
        return eval_rel_show(cmds);

    eval_error("Unknown command");
    return -1;
}

static int
eval_rel_show(char **cmds){
    int ndx = 0;
    int rel_ndx = 0;

    ndx = eval_ndx(cmds);
    if (ndx == -1) return -1;
    cmds++;

    rel_ndx = eval_ndx(cmds);
    if (rel_ndx == -1) return -1;
    cmds++;

    if (! is_last_cmd(cmds)) {
        eval_error("Too many argument");
        return -1;
    }
    const Elf64_Shdr *ps = get_shdr(ndx);
    if (ps == NULL) {
        eval_error("No such an entry");
        return -1;
    }
    Elf64_Rel *prel = (Elf64_Rel *)malloc(ps->sh_entsize);
    if (read_reltbl(prel, rel_ndx, ps) == -1) {
        FREE_IF_EXIST(prel);
        return -1;
    }

    print_relent(prel);
    FREE_IF_EXIST(prel);
    return 0;
}
