#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/elf.h>

#include "seg_cmd.h"
#include "utils_cmd.h"
#include "analy_seg.h"
#include "analy_cmd.h"
#include "analy_utils.h"
#include "elf_analyzer.h"

static int eval_seg_dump(char **cmds);

int
eval_seg(char **cmds) {
    if (is_last_cmd(cmds)) {
        eval_error("Too few argument");
        return -1;
    }

    char *cmd = cmds[0];
    cmds++;
    if (IS_TOK(cmd, dump))
        return eval_seg_dump(cmds);

    eval_error("Unknown command");
    return -1;
}

static int
eval_seg_dump(char **cmds) {
    int ndx = 0;
    ndx = eval_ndx(cmds);
    if (ndx == -1) return -1;
    cmds++;

    DUMP_TYPE type = HEX;
    if (is_last_cmd(cmds)) goto DUMP;
    type = eval_dump_type(cmds);
    if (type == NA_DUMP_TYPE) return -1;
    cmds++;

DUMP: ;
    if (! is_last_cmd(cmds)) {
        eval_error("Too many argument");
        return -1;
    }
    const Elf64_Phdr *pp = get_phdr(ndx);
    if (pp == NULL) {
        eval_error("No such an entry");
        return -1;
    }
    print_seg_dump(pp, type);

    return 0;
}
