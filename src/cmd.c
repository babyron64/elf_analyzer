#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <linux/elf.h>

#include "analy_cmd.h"
#include "analy_ctrl.h"
#include "analy_eval.h"
#include "elf_analyzer.h"

int
parse_line(char cmds[][MAX_CMD_LEN], char *inputs) {
    char *p = strtok(inputs, " ");
    int i = 0;
    while (1) {
        if (p == NULL || i == MAX_TOK_NUM)
            break;
        for (char *q=p; *q!='\0'; q++) if (*q=='\n') *q='\0';
        strcpy(cmds[i++], p);
        p = strtok(NULL, " ");
    }
    return i;
}

int
eval(int cmdc, char cmds[][MAX_CMD_LEN]) {
    if (cmdc == 0) {
        eval_error("No command input");
        return -1;
    }
    int ix = 0;
    char *cmd = cmds[ix];
    if (strcmp(cmd, "quit") == 0)
        return 1;
    else if (strcmp(cmd, "ehdr") == 0)
        return CMD_CALL(eval_ehdr, cmdc, ix, cmds);
    else if (strcmp(cmd, "phdr") == 0)
        return CMD_CALL(eval_phdr, cmdc, ix, cmds);
    else if (strcmp(cmd, "shdr") == 0)
        return CMD_CALL(eval_shdr, cmdc, ix, cmds);
    else if (strcmp(cmd, "seg") == 0)
        return CMD_CALL(eval_seg, cmdc, ix, cmds);
    else if (strcmp(cmd, "sec") == 0)
        return CMD_CALL(eval_sec, cmdc, ix, cmds);
    return -1;
}

int
eval_error(char *mes) {
    fprintf(stderr, "%s\n", mes);
    return 0;
}
