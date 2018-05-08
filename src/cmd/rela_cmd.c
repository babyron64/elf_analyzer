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

static int eval_rela_read(char **cmds);

int
eval_rela(char **cmds) {
    if (is_last_cmd(cmds)) {
        eval_error("Unknown command");
        return -1;
    }

    char *cmd = cmds[0];
    cmds++;

    if (IS_TOK(cmd, read))
        return eval_rela_read(cmds);

    eval_error("Unknown command");
    return -1;
}

static int
eval_rela_read(char **cmds) {
    int ndx = 0;
    int str_ndx = 0;

    ndx = eval_ndx(cmds);
    if (ndx == -1) return -1;
    cmds++;

    str_ndx = eval_ndx(cmds);
    if (str_ndx == -1) return -1;
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
    Elf64_Rela *prela = (Elf64_Rela *)malloc(ps->sh_entsize);
    if (read_relatbl(prela, str_ndx, ps) == -1) {
        FREE_IF_EXIST(prela);
        return -1;
    }

    print_relaent(prela);
    FREE_IF_EXIST(prela);
    return 0;
}
