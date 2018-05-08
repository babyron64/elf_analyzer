#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/elf.h>

#include "ehdr_cmd.h"
#include "utils_cmd.h"
#include "analy_elf.h"
#include "analy_sec.h"
#include "analy_cmd.h"
#include "elf_analyzer.h"

static int eval_dyn_read(char **cmds);

int
eval_dyn(char **cmds) {
    if (is_last_cmd(cmds)) {
        eval_error("Unknown command");
        return -1;
    }

    char *cmd = cmds[0];
    cmds++;
    if (IS_TOK(cmd, read))
        return eval_dyn_read(cmds);

    eval_error("Unknown command");
    return -1;
}

static int
eval_dyn_read(char **cmds){
    int ndx = 0;
    int dyn_ndx = 0;

    ndx = eval_ndx(cmds);
    if (ndx == -1) return -1;
    cmds++;

    dyn_ndx = eval_ndx(cmds);
    if (dyn_ndx == -1) return -1;
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
    Elf64_Dyn *pdyn = (Elf64_Dyn *)malloc(ps->sh_entsize);
    if (read_dyntbl(pdyn, dyn_ndx, ps) == -1) {
        FREE_IF_EXIST(pdyn);
        return -1;
    }

    print_dynent(pdyn);
    FREE_IF_EXIST(pdyn);
    return 0;
}
