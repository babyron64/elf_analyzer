#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/elf.h>

#include "analy_ctrl.h"
#include "elf_analyzer.h"

static int loop();
/*** researved for debug purposes
 * Uncomment the following line to use it.
 ***/
/** #define DEBUG_PRINT **/
#ifdef DEBUG_PRINT
static int print_info();
#endif

int
repl() {
    loop();
    return 0;
}

static int
loop() {
    char line[128];

    while (1) {
        char **cmds;
        int res;
        printf("(elf_analyzer) ");
        fgets(line, 128, stdin);
        cmds = parse_line(line);
        if (cmds == NULL) continue;
        res = eval(cmds);
        if (res == 1)
            break;
    }

    return 0;
}

#ifdef DEBUG_PRINT
static int
print_info() {
    /** const Elf64_Ehdr *p_ehdr64 = get_ehdr(); */
    /** const Elf64_Shdr *p_shstr64 = get_shstr(); */

    // Your code here

    return 0;
}
#endif
