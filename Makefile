CC=gcc

SRC=./src
BIN=./bin

FLAGS=-I ./include -g -O0

MAIN=$(SRC)/main.c
LOAD=$(SRC)/elf_load.c

OBJS=$(BIN)/main.o $(BIN)/load.o $(BIN)/repl.o $(BIN)/cmd.o
OBJS+=$(BIN)/elfhdr.o $(BIN)/segment.o $(BIN)/section.o $(BIN)/shstr.o $(BIN)/utils.o

HDRS=./include/*

OUTPUT=./analyelf.out

.PHONY: all clean

all: $(OUTPUT)

clean:
	rm bin/* analyelf.out

$(OUTPUT): $(OBJS)
	$(CC) $(FLAGS) $(OBJS) -o $(OUTPUT)

$(BIN)/%.o: $(SRC)/%.c $(HDRS)
	$(CC) $(FLAGS) -c $< -o $@
