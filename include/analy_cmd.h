#ifndef ANALY_CMD_INCLUDED
#define ANALY_CMD_INCLUDED

#define MAX_CMD_LEN 8
#define MAX_TOK_NUM 8

typedef char CMD_ARGS[][MAX_CMD_LEN];

#define CMD_CALL(cmd, cmdc, ix, cmds) \
    (cmdc)-1 > 0?cmd((cmdc)-1, (ix)+1, cmds):cmd(0, 0, NULL)

int eval(int cmdc, char cmds[][MAX_CMD_LEN]);
int parse_line(char cmds[][MAX_CMD_LEN], char *line);
int eval_error(char *mes);

#endif
