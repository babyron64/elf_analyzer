#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <linux/elf.h>

#include "analy_cmd.h"
#include "analy_ctrl.h"
#include "analy_eval.h"
#include "elf_analyzer.h"

/***
 * User defined command extension implementation
 * When you want to implement your own command group,
 * you have to do two things in this file.
 * 1. Determin whether the first command of cmds argument
 *    matches your own command group name. You can use
 *    IS_TOK macro defined in include/analy_cmd.h to do it.
 * 2. Navigate the control to your own group's root
 *    function, and then return the return value from your
 *    command group.
 * See the existing branched for detailed convention. Also
 * see the comment in src/cmd/ehdr_cmd.c file for the
 * other things you have to do.
 ***/
int
eval(char **cmds) {
    if (cmds[0][0] == '\0') {
        eval_error("No command input");
        return -1;
    }
    char *cmd = cmds[0];
    cmds++;
    if (IS_TOK(cmd, quit))
        return 1;
    else if (IS_TOK(cmd, ehdr))
        return eval_ehdr(cmds);
    else if (IS_TOK(cmd, phdr))
        return eval_phdr(cmds);
    else if (IS_TOK(cmd, shdr))
        return eval_shdr(cmds);
    else if (IS_TOK(cmd, seg))
        return eval_seg(cmds);
    else if (IS_TOK(cmd, sec))
        return eval_sec(cmds);
    else if (IS_TOK(cmd, sym))
        return eval_sym(cmds);
    else if (IS_TOK(cmd, str))
        return eval_str(cmds);
    else if (IS_TOK(cmd, rel))
        return eval_rel(cmds);
    else if (IS_TOK(cmd, rela))
        return eval_rela(cmds);

    eval_error("Unknown command");
    return -1;
}

int
eval_error(char *mes) {
    fprintf(stderr, "%s\n", mes);
    return 0;
}
