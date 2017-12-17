#include <stdio.h>
#include <string.h>
#include <linux/elf.h>

#include "ehdr_cmd.h"
#include "analy_elf.h"
#include "analy_cmd.h"
#include "elf_analyzer.h"

static int eval_ehdr_show(int cmdc, int ix, char cmds[][MAX_CMD_LEN]);

int
eval_ehdr(int cmdc, int ix, char cmds[][MAX_CMD_LEN]) {
    if (cmdc == 0)
        return CMD_CALL(eval_ehdr_show, cmdc, ix, cmds);

    char *cmd = cmds[ix];
    
    if (strcmp(cmd, "show") == 0)
        return CMD_CALL(eval_ehdr_show, cmdc, ix, cmds);

    return -1;
}

static int
eval_ehdr_show(int cmdc, int ix, char cmds[][MAX_CMD_LEN]) {
    if (cmdc == 0) {
        print_ehdr();
        return 0;
    }

    eval_error("Too many arguments");
    return -1;
}
