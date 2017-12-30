#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/elf.h>

#include "analy_ctrl.h"
#include "elf_analyzer.h"

static int loop();
static int print_info();

int
repl() {
    loop();
    return 0;
}

static int
loop() {
    char line[128];

    while (1) {
        char cmds[MAX_TOK_NUM][MAX_CMD_LEN] = {{0}};
        int cmdc, res;
        printf("(elf_analyzer) ");
        fgets(line, 128, stdin);
        cmdc = parse_line(cmds, line);
        if (cmdc > MAX_TOK_NUM) {
            fprintf(stderr, "Too many commands\n");
            continue;
        }
        res = eval(cmdc, cmds);
        if (res == 1)
            break;
    }

    return 0;
}

/*** researved for debug purposes ***/
static int
print_info() {
    /** const Elf64_Ehdr *p_ehdr64 = get_ehdr(); */
    /** const Elf64_Shdr *p_shstr64 = get_shstr(); */

    // Your code here

    return 0;
}
