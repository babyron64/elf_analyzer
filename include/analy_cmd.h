#ifndef ANALY_CMD_INCLUDED
#define ANALY_CMD_INCLUDED

#define MAX_CMD_LEN 8
#define MAX_TOK_NUM 8

#define IS_TOK(val, tok) \
    strcmp(val, #tok) == 0

typedef enum {
    NORMAL = 0,
    QUIT,
    CD,
    ROOT
} CTRL_CMD;


int eval(char **cmds);
int eval_error(char *mes);
CTRL_CMD get_ctrl_type(char *cmd);

int parser_init();
char** parse_line(char *line);
int save_prefix(char **pf);

#endif
