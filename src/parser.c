#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <linux/elf.h>

#include "analy_cmd.h"
#include "analy_ctrl.h"
#include "analy_eval.h"
#include "elf_analyzer.h"

static char *esc_newline(char *p);

static char *cmds_buf[MAX_TOK_NUM + 1];
static char line[MAX_TOK_NUM * MAX_CMD_LEN + 1];
static char *tmp_buf[MAX_TOK_NUM + 1];
static char tmp_line[MAX_TOK_NUM * MAX_CMD_LEN + 1];
static int base_ndx = 0;

int
parser_init() {
    for (int i=0; i<=MAX_TOK_NUM; i++) {
        cmds_buf[i] = &line[MAX_CMD_LEN * i];
        tmp_buf[i] = &tmp_line[MAX_CMD_LEN * i];
    }
    cmds_buf[MAX_TOK_NUM][0] = '\0';
    tmp_buf[MAX_TOK_NUM][0] = '\0';
    return 0;
}

/***
 * NULL is a marker that indicates the end of commands list
 ***/
char **
parse_line(char *inputs) {
    char *p = esc_newline(strtok(inputs, " "));
    int i = base_ndx;
    char **cmds=cmds_buf;
    CTRL_CMD type = get_ctrl_type(p);
    if (type != NORMAL) {
        if (type == ROOT)
            cmds = tmp_buf; 
        i = 0;
    }

    while (p != NULL) {
        if (i >= MAX_TOK_NUM) {
            fprintf(stderr, "Too many argument");
            return NULL;
        }
        if (*p != '\0')
            /*** (TODO) the length of strings should be checked ***/
            strcpy(cmds[i++], p);
        p = esc_newline(strtok(NULL, " "));
    }
    cmds[i][0] = '\0';
    return cmds;
}

static char *
esc_newline(char *p) {
    if (p == NULL) return p;
    for (char *q=p; *q!='\0'; q++) if (*q=='\n') *q='\0';
    return p;
}

int
save_prefix(char **pf) {
    int i = 0;
    for (; pf[i][0] != '\0'; i++)
        strcpy(cmds_buf[i], pf[i]);
    cmds_buf[i][0] = '\0';
    base_ndx = i;
    return 0;
}
