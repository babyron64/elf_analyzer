CC=gcc
MAKE=make --no-print-directory

BIN=./bin

FLAGS=-I $(INC) -g -O0

OBJS=$(BIN)/main.o $(BIN)/load.o $(BIN)/repl.o $(BIN)/cmd.o
OBJS+=$(BIN)/elfhdr.o $(BIN)/segment.o $(BIN)/section.o $(BIN)/utils.o
OBJS+=$(BIN)/section/shstr.o $(BIN)/section/strtbl.o $(BIN)/section/symtbl.o $(BIN)/section/reltbl.o $(BIN)/section/relatbl.o
OBJS+=$(BIN)/cmd/ehdr_cmd.o $(BIN)/cmd/phdr_cmd.o $(BIN)/cmd/shdr_cmd.o $(BIN)/cmd/seg_cmd.o $(BIN)/cmd/sec_cmd.o

OUTPUT=./analyelf.out

.PHONY: all clean pre

all: pre $(OUTPUT)

pre:
	$(MAKE)  -C ./src
	$(MAKE)  -C ./src/section
	$(MAKE)  -C ./src/cmd

clean:
	$(MAKE) clean -C ./src
	$(MAKE) clean -C ./src/section
	$(MAKE) clean -C ./src/cmd
	rm analyelf.out

$(OUTPUT): $(OBJS)
	$(CC) $(FLAGS) $(OBJS) -o $(OUTPUT)
