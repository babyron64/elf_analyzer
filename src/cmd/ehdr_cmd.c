#include <stdio.h>
#include <string.h>
#include <linux/elf.h>

#include "utils_cmd.h"
#include "analy_eval.h"
#include "analy_elf.h"
#include "analy_cmd.h"
#include "elf_analyzer.h"

static int eval_ehdr_show(char **cmds);

/***
 *
 * *** USER DEFINED COMMAND IMPLEMENTATION ***
 *
 * In order to add a new command group, you have to
 * do three things:
 * 1. Write a function that handles all the accesses
 *    to the command group. eval_ehdr(char **cmds)
 *    below is, for instance, a root function
 *    that navigates an access to each utility of the
 *    ehdr command group - show (in this case, ehdr
 *    command group only has one command, but a command
 *    group, in general, has more than one commands
 *    that would be called in a nested way. See
 *    sec_cmd.c for an example). You should expose only
 *    the root function to global space, that is, the
 *    functions that serve specific utilities should 
 *    not be global-scoped. The example below,
 *    eval_ehdr_show(char **cmds) is static and so it
 *    is not global-scoped. There is also a convention
 *    of naming functions. The name of a function that
 *    is a member of a command group should be like this:
 *       eval_(command group name)/(1st)/(2nd)/.../(nth).
 *    (1st), (2nd) and (nth) mean the name of the 
 *    corresponding stage function, that is, (nth) is the
 *    nth stage function's name. Since the root function
 *    is the "gate" of command group, there is no stage 
 *    before the execution of it. So, the root function's
 *    name should be as such:
 *       eval_(command group name)
 *    In order to reinforce your understanding, Let's take
 *    eval_ehdr_show(char **cmds) function below as an
 *    example. "ehdr" is the name of the command group.
 *    "show" is the name of the first stage function's
 *    name. The function in each stage including the root, 
 *    takes only one argument, which is commands list to
 *    be interpreted. The meanings of the argument is
 *    explained later in this comment.
 * 2. Add a header file for your own command group under
 *    include/cmd directory. The name of the file should
 *    follow the convention: 
 *      (the root function name)_cmd.h
 *    You do not need to specify anything when re-compile
 *    the program. The header file will be automatically
 *    loaded as long as it resides in the proper location.
 * 3. Add a new branch for the command group to the switch
 *    statement in eval(char **cmd) function in cmd.c
 *    file. You need to follow a convention when write the
 *    branch. The convention is explained in the comment
 *    written above eval(char **cmds) function.
 *
 * The only one argument, cmds, is declared as char **
 * type. This contains the array of commands. The command
 * is a string or char *, which results in the type of
 * cmds beeing char **. Each stage of interpretaion of
 * commands takes zero or more commands from cmds and
 * moves cmds so that it points the next command.
 * 
 * I offer you some functions that may help you implement
 * your command group. One of them is
 * is_last_cmd(char **cmds) function that checks whether
 * the current command list, cmds, contains any command
 * to be read. There are other functions that may help
 * you implement your command group, such as:
 *    eval_ndx(char **cmd)
 *    eval_dump_type(char **cmds)
 *    eval_error(char *mes).
 * These commands are written in src/cmd/utils_cmd.c.
 * You can add your own helper functions to the file. 
 ***/
int
eval_ehdr(char **cmds) {
    if (is_last_cmd(cmds))
        return eval_ehdr_show(cmds);
    
    char *cmd = cmds[0];
    cmds++; 
    if (IS_TOK(cmd, show))
        return eval_ehdr_show(cmds);

    eval_error("Unknown command");
    return -1;
}

static int
eval_ehdr_show(char **cmds){
    if (is_last_cmd(cmds)) {
        print_ehdr();
        return 0;
    }

    eval_error("Too many arguments");
    return -1;
}
