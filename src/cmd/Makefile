CC=gcc

SRC=.
INC=../../include
INC_CMD=$(INC)/cmd
BIN=../../bin/cmd

FLAGS=-I $(INC) -I $(INC_CMD) -g -O0

OBJS=$(BIN)/ehdr_cmd.o $(BIN)/phdr_cmd.o $(BIN)/shdr_cmd.o \
	 $(BIN)/seg_cmd.o $(BIN)/sec_cmd.o

HDRS=$(INC)/* $(INC_CMD)/*

.PHONY: all clean

all: $(BIN) $(OBJS)

clean:
	rm $(BIN)/*.o

$(BIN)/%.o: $(SRC)/%.c $(HDRS)
	$(CC) $(FLAGS) -c $< -o $@

$(BIN):
	mkdir -p $(BIN)
