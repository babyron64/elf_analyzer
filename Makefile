CC=gcc
MAKE=make --no-print-directory

BIN=./bin

FLAGS=-I $(INC) -g -O0

OBJS=$(BIN)/main.o $(BIN)/load.o $(BIN)/repl.o $(BIN)/cmd.o
OBJS+=$(BIN)/elfhdr.o $(BIN)/segment.o $(BIN)/section.o $(BIN)/utils.o
OBJS+=$(BIN)/section/shstr.o

OUTPUT=./analyelf.out

.PHONY: all clean pre

all: pre $(OUTPUT)

clean:
	$(MAKE) clean -C ./src
	rm analyelf.out

pre:
	$(MAKE) -C ./src

$(OUTPUT):
	$(CC) $(FLAGS) $(OBJS) -o $(OUTPUT)
