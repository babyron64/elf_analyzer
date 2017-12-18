#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/elf.h>

#include "ehdr_cmd.h"
#include "analy_sec.h"
#include "analy_elf.h"
#include "analy_cmd.h"
#include "elf_analyzer.h"

static int eval_str_show(int cmdc, int ix, char cmds[][MAX_CMD_LEN]);
static int eval_str_read(int cmdc, int ix, char cmds[][MAX_CMD_LEN]);

int
eval_str(int cmdc, int ix, char cmds[][MAX_CMD_LEN]) {
    if (cmdc == 0) {
        eval_error("Unknown command");
        return -1;
    }

    char *cmd = cmds[ix];
    
    if (strcmp(cmd, "show") == 0)
        return CMD_CALL(eval_str_show, cmdc, ix, cmds);
    else if (strcmp(cmd, "read") == 0)
        return CMD_CALL(eval_str_read, cmdc, ix, cmds);

    eval_error("Unknown command");
    return -1;
}

static int
eval_str_show(int cmdc, int ix, char cmds[][MAX_CMD_LEN]) {
    int ndx = 0;
    int str_ndx = 0;
    if (cmdc == 0) {
        eval_error("Too few argument");
        return -1;
    }

    char *cmd = cmds[ix];
    if (strcmp(cmd, "0") == 0) goto SHOW;
    ndx = atoi(cmd);
    if (ndx == 0) {
        eval_error("Illegal argument");
        return -1;
    }

SHOW: ;
    const Elf64_Shdr *ps = get_shdr(ndx);
    if (ps == NULL) {
        eval_error("No such an entry");
        return -1;
    }
    char *buf = (char *)malloc(sizeof(char) * ps->sh_size+1);
    buf[ps->sh_size] = '\0';
    if (read_strtbl(buf, ps, 0, ps->sh_size) == -1) {
        FREE_IF_EXIST(buf);
        return -1;
    }

    char *ptr = buf;
    int i = 0;
    /***
     * bytes=\0abc\0\0def\0gh
     * abc
     * def
     * gh
     ***/
    while (i < ps->sh_size) {
        while (*ptr != '\0') {
            putchar(*ptr);
            ptr++; i++;
            if (i >= ps->sh_size)
                goto END;
        }
        putchar('\n');
        while (*ptr == '\0') {
            ptr++; i++;
            if (i >= ps->sh_size)
                goto END;
        }
    }
END: ;

    FREE_IF_EXIST(buf);
    return 0;
}

static int
eval_str_read(int cmdc, int ix, char cmds[][MAX_CMD_LEN]) {
    int ndx = 0;
    int str_ndx = 0;
    if (cmdc == 0) {
        eval_error("Too few argument");
        return -1;
    }

NDX: ;
    char *cmd = cmds[ix];
    if (strcmp(cmd, "0") == 0) goto STR_NDX;
    ndx = atoi(cmd);
    if (ndx == 0) {
        eval_error("Illegal argument");
        return -1;
    }

STR_NDX: ;
    if (cmdc == 1) goto SHOW;
    cmd = cmds[ix+1];
    if (strcmp(cmd, "0") == 0) goto STR_NDX;
    str_ndx = atoi(cmd);
    if (str_ndx == 0) {
        eval_error("Illegal argument");
        return -1;
    }

SHOW: ;
    const Elf64_Shdr *ps = get_shdr(ndx);
    if (ps == NULL) {
        eval_error("No such an entry");
        return -1;
    }
    char *buf = (char *)malloc(sizeof(char) * ps->sh_size-str_ndx+1);
    buf[ps->sh_size-str_ndx] = '\0';
    if (read_strtbl(buf, ps, str_ndx, ps->sh_size-str_ndx) == -1) {
        FREE_IF_EXIST(buf);
        return -1;
    }

    printf("%s\n", buf);
    FREE_IF_EXIST(buf);
    return 0;
}
