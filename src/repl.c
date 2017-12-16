#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/elf.h>

#include "analy_ctrl.h"
#include "elf_analyzer.h"

static int loop();
static int parse_line(char cmds[][MAX_TOK_NUM], char *line);
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
        char cmds[MAX_CMD_LEN][MAX_TOK_NUM] = {{0}};
        int res;
        printf("(elf_analyzer) ");
        fgets(line, 128, stdin);
        parse_line(cmds, line);
        res = eval(cmds);
        if (res == 1)
            break;
    }

    return 0;
}

static int
parse_line(char cmds[][MAX_TOK_NUM], char *inputs) {
    char *p = strtok(inputs, " ");
    Tok tok;

    int i = 0;
    while (1) {
        if (p == NULL || i == MAX_TOK_NUM)
            break;
        for (char *q=p; *q!='\0'; q++) if (*q=='\n') *q='\0';
        strcpy(cmds[i++], p);
        p = strtok(NULL, " ");
    }

    return 0;
}

/*** researved for debug purposes ***/
static int
print_info() {
    const Elf64_Ehdr *p_ehdr64 = get_ehdr();
    const Elf64_Shdr *p_shstr64 = get_shstr();

    // Your code here

    return 0;
}
