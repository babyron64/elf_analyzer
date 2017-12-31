#include <stdlib.h>
#include <string.h>
#include <elf.h>

#include "utils_cmd.h"
#include "analy_cmd.h"
#include "analy_utils.h"

int
eval_ndx(char **cmds) {
    if (is_last_cmd(cmds)) {
        eval_error("Too few argument");
        return -1;
    }
    char *cmd = cmds[0];
    int ndx = atoi(cmd);
    if (IS_TOK(cmd, 0)) return 0;
    if (ndx <= 0) {
        eval_error("Illegal argument");
        return -1;
    }
    return ndx;
}

DUMP_TYPE
eval_dump_type(char **cmds) {
    if (is_last_cmd(cmds)) {
        eval_error("Too few argument");
        return NA_DUMP_TYPE;
    }
    char *cmd = cmds[0];
    if (IS_TOK(cmd, h) || IS_TOK(cmd, hex))
        return HEX;
    else if (IS_TOK(cmd, b) || IS_TOK(cmd, bin))
        return BIN;
    else if (IS_TOK(cmd, a) || IS_TOK(cmd, asc) || IS_TOK(cmd, ascii))
        return ASC;
    else {
        eval_error("Illegal argument");
        return NA_DUMP_TYPE;
    }
}

int
is_last_cmd(char **cmds) {
    return cmds[0][0] == '\0';
}
