#ifndef UTILS_CMD_INCLUDED
#define UTILS_CMD_INCLUDED

#include "analy_cmd.h"
#include "analy_utils.h"

int eval_ndx(int cmdc, int ix, char cmds[][MAX_CMD_LEN]);
DUMP_TYPE eval_dump_type(int cmdc, int ix, char cmds[][MAX_CMD_LEN]);

#endif
