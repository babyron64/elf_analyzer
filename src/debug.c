#include <stdio.h>

int
print_cmds(char **cmds) {
    for (; **cmds != '\0'; cmds++)
        printf("%s ", *cmds);
    printf("\n");
    return 0;
}
