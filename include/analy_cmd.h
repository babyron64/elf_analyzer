#ifndef ANALY_CMD_INCLUDED
#define ANALY_CMD_INCLUDED

#define MAX_CMD_LEN 8
#define MAX_TOK_NUM 8

#define IS_TOK(val, tok) \
    strcmp(val, #tok) == 0

int eval(char **cmds);
char** parse_line(char *line);
int eval_error(char *mes);

int parser_init();
int release_cmdbase();

#endif
