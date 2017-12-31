#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <linux/elf.h>

#include "analy_cmd.h"
#include "analy_ctrl.h"
#include "analy_eval.h"
#include "elf_analyzer.h"

static char *cmds[MAX_TOK_NUM + 1];
static char line[MAX_TOK_NUM * MAX_CMD_LEN + 1];

int
parser_init() {
    for (int i=0; i<=MAX_TOK_NUM; i++)
        cmds[i] = &line[MAX_CMD_LEN * i];
    cmds[MAX_TOK_NUM][0] = '\0';
    return 0;
}

/***
 * NULL is a marker that indicates the end of commands list
 ***/
char **
parse_line(char *inputs) {
    char *p = strtok(inputs, " ");
    int i = 0;
    while (p != NULL && i < MAX_TOK_NUM) {
        for (char *q=p; *q!='\0'; q++) if (*q=='\n') *q='\0';
        if (*p != '\0')
            /*** (TODO) the length of strings should be checked ***/
            strcpy(cmds[i++], p);
        p = strtok(NULL, " ");
    }
    cmds[i][0] = '\0';
    return cmds;
}
