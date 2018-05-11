#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/elf.h>

#include "utils_cmd.h"
#include "analy_eval.h"
#include "analy_sec.h"
#include "analy_elf.h"
#include "analy_cmd.h"
#include "elf_analyzer.h"

static int eval_str_list(char **cmds);
static int eval_str_show(char **cmds);

int
eval_str(char **cmds) {
    if (is_last_cmd(cmds)) {
        eval_error("Unknown command");
        return -1;
    }

    char *cmd = cmds[0];
    cmds++;
    if (IS_TOK(cmd, list))
        return eval_str_list(cmds);
    else if (IS_TOK(cmd, show))
        return eval_str_show(cmds);

    eval_error("Unknown command");
    return -1;
}

static int
eval_str_list(char **cmds) {
    int ndx = 0;

    ndx = eval_ndx(cmds);
    if (ndx == -1) return -1;
    cmds++;

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
eval_str_show(char **cmds) {
    int ndx = 0;
    int str_ndx = 0;

    ndx = eval_ndx(cmds);
    if (ndx == -1) return -1;
    cmds++;

    str_ndx = eval_ndx(cmds);
    if (str_ndx == -1) return -1;
    cmds++;

    if (! is_last_cmd(cmds)) {
        eval_error("Too many argument");
        return -1;
    }
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
