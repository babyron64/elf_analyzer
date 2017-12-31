#include <stdlib.h>
#include <string.h>
#include <elf.h>

#include "utils_cmd.h"
#include "analy_cmd.h"
#include "analy_utils.h"

int
eval_ndx(int cmdc, int ix, char cmds[][MAX_CMD_LEN]) {
    char *cmd = cmds[ix];
    int ndx = atoi(cmd);
    if (strcmp(cmd, "0") == 0) return 0;
    if (ndx <= 0) {
        eval_error("Illegal argument");
        return -1;
    }
    return ndx;
}

DUMP_TYPE
eval_dump_type(int cmdc, int ix, char cmds[][MAX_CMD_LEN]) {
    if (cmdc == 0) return HEX;
    char *cmd = cmds[ix];
    if (strcmp(cmd, "h") == 0 || strcmp(cmd, "hex") == 0)
        return HEX;
    else if (strcmp(cmd, "b") == 0 || strcmp(cmd, "bin") == 0)
        return BIN;
    else if (strcmp(cmd, "a") == 0 || strcmp(cmd, "asc") == 0 || strcmp(cmd, "ascii") == 0)
        return ASC;
    else {
        eval_error("Illegal argument");
        return NA_DUMP_TYPE;
    }
}
