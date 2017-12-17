CC=gcc

SRC=.
INC=../../include
BIN=../../bin/section

FLAGS=-I $(INC) -g -O0

OBJS=$(BIN)/shstr.o $(BIN)/strtbl.o $(BIN)/symtbl.o $(BIN)/reltbl.o $(BIN)/relatbl.o

HDRS=$(INC)/*

.PHONY: all clean

all: $(BIN) $(OBJS)

clean:
	rm $(BIN)/*.o

$(BIN)/%.o: $(SRC)/%.c $(HDRS)
	$(CC) $(FLAGS) -c $< -o $@

$(BIN):
	mkdir -p $(BIN)
