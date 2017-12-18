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
    if (argc == 2)
        repl();
    else {
        if (argc-2 > MAX_TOK_NUM)
            fprintf(stderr, "Too many arguments\n");
        char cmds[MAX_TOK_NUM][MAX_CMD_LEN] = {{0}};
        for (int i=0; i<argc-2; i++)
            strcpy(cmds[i], argv[i+2]); 
        eval(argc-2, cmds);
    }

    release();

    close_elf();

    return 0;
}
