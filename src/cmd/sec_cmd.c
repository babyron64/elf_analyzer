#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/elf.h>

#include "sec_cmd.h"
#include "utils_cmd.h"
#include "analy_sec.h"
#include "analy_cmd.h"
#include "analy_utils.h"
#include "elf_analyzer.h"

static int eval_sec_dump(char **cmds);
static int eval_sec_list(char **cmds);

int
eval_sec(char **cmds) {
    if (is_last_cmd(cmds)) {
        eval_error("Too few argument");
        return -1;
    }

    char *cmd = cmds[0];
    cmds++;
    if (IS_TOK(cmd, dump))
        return eval_sec_dump(cmds);
    else if (IS_TOK(cmd, list))
        return eval_sec_list(cmds);

    eval_error("Unknown command");
    return -1;
}

static int
eval_sec_dump(char **cmds) {
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
    const Elf64_Shdr *ps = get_shdr(ndx);
    if (ps == NULL) {
        eval_error("No such an entry");
        return -1;
    }
    print_sec_dump(ps, type);

    return 0;
}

static int
eval_sec_list(char **cmds) {
    if (! is_last_cmd(cmds)) {
        eval_error("Too many argument");
        return -1;
    }
    print_sec_list();

    return 0;
}
