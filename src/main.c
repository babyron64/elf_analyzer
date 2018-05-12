#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/elf.h>

#include "analy_elf.h"
#include "analy_seg.h"
#include "analy_sec.h"
#include "analy_ctrl.h"
#include "analy_utils.h"
#include "analy_cmd.h"
#include "elf_analyzer.h"

#define LINE_BUF_LEN 128

int
load() {
    load_ehdr();
    load_ptbl();
    load_stbl();
    load_shstr();
    return 0;
}

int
release() {
    release_ehdr();
    release_ptbl();
    release_stbl();
    release_sec();
    return 0;
}

int
main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "No input file\n");
        return -1;
    }

    char *fname = argv[1];
    if (elf_open(fname) == -1) {
        return -1;
    }

    load();
    parser_init();

    if (argc == 2)
        repl();
    else {
        if (argc-2 > MAX_TOK_NUM)
            fprintf(stderr, "Too long command\n");

        char line[LINE_BUF_LEN];
        int ix = 0;
        for (int i=2; i< argc; i++) {
            for (char *ptr = argv[i]; *ptr != '\0' && ix < LINE_BUF_LEN-1; ptr++)
                line[ix++] = *ptr; 
            line[ix++] = ' ';
        }
        while (ix < LINE_BUF_LEN)
            line[ix++] = '\0';
        line[LINE_BUF_LEN-1] = '\0';

        char **cmds;
        cmds = parse_line(line);
        if (cmds == NULL) return -1;
        eval(cmds);
    }

    release();

    close_elf();

    return 0;
}
