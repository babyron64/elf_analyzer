#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/elf.h>

#include "shdr_cmd.h"
#include "utils_cmd.h"
#include "analy_sec.h"
#include "analy_cmd.h"
#include "elf_analyzer.h"

static int eval_shdr_show(char **cmds);

int
eval_shdr(char **cmds) {
    if (is_last_cmd(cmds))
        return eval_shdr_show(cmds);

    char *cmd = cmds[0];
    cmds++;
    if (IS_TOK(cmd, show))
        return eval_shdr_show(cmds);

    eval_error("Unknown command");
    return -1;
}

static int
eval_shdr_show(char **cmds) {
    int ndx = 0;

    ndx = eval_ndx(cmds);
    if (ndx == -1) return -1;
    cmds++;

    if (! is_last_cmd(cmds)) {
        eval_error("Too many arguments");
        return -1;
    }
    const Elf64_Shdr *ps = get_shdr(ndx);
    if (ps == NULL) {
        eval_error("No such an entry");
        return -1;
    }
    print_shdr(ps);

    return 0;
}
