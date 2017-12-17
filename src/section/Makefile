CC=gcc
MAKE=make --no-print-directory

SRC=.
INC=../../include
BIN=../../bin/section

FLAGS=-I $(INC) -g -O0

OBJS=$(BIN)/shstr.o

HDRS=$(INC)/*

.PHONY: all clean

all: $(BIN) $(OBJS)

clean:
	rm $(BIN)/*.o

$(BIN)/%.o: $(SRC)/%.c $(HDRS)
	$(CC) $(FLAGS) -c $< -o $@

$(BIN):
	mkdir -p $(BIN)
