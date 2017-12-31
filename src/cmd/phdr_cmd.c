#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/elf.h>

#include "phdr_cmd.h"
#include "utils_cmd.h"
#include "analy_seg.h"
#include "analy_cmd.h"
#include "elf_analyzer.h"

static int eval_phdr_show(char **cmds);

int
eval_phdr(char **cmds){
    if (is_last_cmd(cmds)) {
        eval_error("Unknown command");
        return -1;
    }

    char *cmd = cmds[0];
    cmds++; 
    if (IS_TOK(cmd, show))
        return eval_phdr_show(cmds);

    eval_error("Unknown command");
    return -1;
}

static int
eval_phdr_show(char **cmds) {
    int ndx = 0;

    ndx = eval_ndx(cmds);
    if (ndx == -1) return -1;
    cmds++;

    if (! is_last_cmd(cmds)) {
        eval_error("Too many arguments");
        return -1;
    }
    const Elf64_Phdr *pp = get_phdr(ndx);
    if (pp == NULL) {
        eval_error("No such an entry");
        return -1;
    }
    print_phdr(pp);

    return 0;
}
