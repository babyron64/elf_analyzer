CC=gcc
MAKE=make --no-print-directory

SRC=.
INC=../include
BIN=../bin

FLAGS=-I $(INC) -g -O0

OBJS=$(BIN)/main.o $(BIN)/load.o $(BIN)/repl.o $(BIN)/cmd.o
OBJS+=$(BIN)/elfhdr.o $(BIN)/segment.o $(BIN)/section.o $(BIN)/utils.o

HDRS=$(INC)/*

.PHONY: all clean pre

all: $(BIN) pre $(OBJS)

clean:
	$(MAKE) clean -C ./section
	rm $(BIN)/*.o

pre:
	$(MAKE) -C ./section

$(BIN)/%.o: $(SRC)/%.c $(HDRS) $(BIN)
	$(CC) $(FLAGS) -c $< -o $@

$(BIN):
	mkdir -p $(BIN)
