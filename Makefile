CC=gcc

SRC=./src
BIN=./bin

FLAGS=-I ./include -g -O0

MAIN=$(SRC)/main.c
LOAD=$(SRC)/elf_load.c

OBJS=$(BIN)/main.o $(BIN)/repl.o
OBJS+=$(BIN)/elfhdr.o $(BIN)/segment.o $(BIN)/section.o

OUTPUT=./analyelf.out

.PHONY: all

all: $(OUTPUT)

$(OUTPUT): $(OBJS)
	$(CC) $(FLAGS) $(OBJS) -o $(OUTPUT)

$(BIN)/%.o: $(SRC)/%.c
	$(CC) $(FLAGS) -c $< -o $@
