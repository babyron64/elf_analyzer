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

static int eval_eh_show(char **cmds);
static int eval_eh_list(char **cmds);

int
eval_eh(char **cmds) {
    if (is_last_cmd(cmds)) {
        eval_error("Unknown command");
        return -1;
    }

    char *cmd = cmds[0];
    cmds++;
    if (IS_TOK(cmd, show))
        return eval_eh_show(cmds);
    else if (IS_TOK(cmd, list))
        return eval_eh_list(cmds);

    eval_error("Unknown command");
    return -1;
}

static int
eval_eh_show(char **cmds){
    int ndx = 0;
    int eh_ndx = 0;

    ndx = eval_ndx(cmds);
    if (ndx == -1) return -1;
    cmds++;

    eh_ndx = eval_ndx(cmds);
    if (eh_ndx == -1) return -1;
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

    Elf64_Eh_Ent *peh;
    if (!(peh = get_eh_frame_ent(ps, eh_ndx))) return -1;

    print_eh_ent(peh);

    return 0;
}

static int
eval_eh_list(char **cmds){
    int ndx = 0;

    ndx = eval_ndx(cmds);
    if (ndx == -1) return -1;
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

    print_eh_list(ps);

    return 0;
}
