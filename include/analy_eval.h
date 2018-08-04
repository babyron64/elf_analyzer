#ifndef ANALY_EVAL_INCLUDED
#define ANALY_EVAL_INCLUDED

#include "analy_cmd.h"

/*** ehdr ***/
int eval_ehdr(char **cmds);

/*** phdr ***/
int eval_phdr(char **cmds);

/** sec **/
int eval_sec(char **cmds);

/** seg **/
int eval_seg(char **cmds);

/** shdr **/
int eval_shdr(char **cmds);

/** str **/
int eval_str(char **cmds);

/** sym **/
int eval_sym(char **cmds);

/** rel **/
int eval_rel(char **cmds);

/** rela **/
int eval_rela(char **cmds);

/** dyn **/
int eval_dyn(char **cmds);

/** eh_frame **/
int eval_eh(char **cmds);

#endif
