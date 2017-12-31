#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/elf.h>

#include "utils_cmd.h"
#include "sec_cmd.h"
#include "analy_sec.h"
#include "analy_cmd.h"
#include "analy_utils.h"
#include "elf_analyzer.h"

static int eval_sec_dump(int cmdc, int ix, char cmds[][MAX_CMD_LEN]);
static int eval_sec_list(int cmdc, int ix, char cmds[][MAX_CMD_LEN]);

int
eval_sec(int cmdc, int ix, char cmds[][MAX_CMD_LEN]) {
    if (cmdc == 0) {
        eval_error("Too few argument");
        return -1;
    }

    char *cmd = cmds[ix];
    if (strcmp(cmd, "dump") == 0)
        return CMD_CALL(eval_sec_dump, cmdc, ix, cmds);
    else if (strcmp(cmd, "list") == 0)
        return CMD_CALL(eval_sec_list, cmdc, ix, cmds);

    eval_error("Unknown command");
    return -1;
}

static int
eval_sec_dump(int cmdc, int ix, char cmds[][MAX_CMD_LEN]) {
    int ndx = 0;
    if (cmdc == 0) {
        eval_error("Too few argument");
        return -1;
    }
    if (cmdc > 2) {
        eval_error("Too many argument");
        return -1;
    }
    ndx = eval_ndx(cmdc--, ix++, cmds);
    if (ndx == -1) return -1;

BASE: ;
    DUMP_TYPE type = HEX;
    if (cmdc == 0) goto DUMP;
    type = eval_dump_type(cmdc--, ix++, cmds);
    if (type == NA_DUMP_TYPE) return -1;

DUMP: ;
    const Elf64_Shdr *ps = get_shdr(ndx);
    if (ps == NULL) {
        eval_error("No such an entry");
        return -1;
    }
    print_sec_dump(ps, type);

    return 0;
}

static int
eval_sec_list(int cmdc, int ix, char cmds[][MAX_CMD_LEN]) {
    if (cmdc > 0) {
        eval_error("Too many argument");
        return -1;
    }
    print_sec_list();

    return 0;
}
