#ifndef UTILS_CMD_INCLUDED
#define UTILS_CMD_INCLUDED

#include "analy_cmd.h"
#include "analy_utils.h"

int eval_ndx(char **cmds);
DUMP_TYPE eval_dump_type(char **cmds);
int is_last_cmd(char **cmds);

#endif
