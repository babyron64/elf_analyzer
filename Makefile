CC=gcc
MAKE=make --no-print-directory

BIN=./bin
SRC=./src
INC=./include

SRCS=$(wildcard $(SRC)/*.c) $(wildcard $(SRC)/section/*.c) $(wildcard $(SRC)/cmd/*.c)
HDRS=$(wildcard $(INC)/*.h) $(wildcard $(INC)/cmd/*.h)
OBJS=$(patsubst $(SRC)/%.c, $(BIN)/%.o, $(SRCS))

FLAGS=-I $(INC) -I $(INC)/cmd -g -O0

OUTPUT=./analyelf.out

.PHONY: all clean

all: $(BIN) $(BIN)/section $(BIN)/cmd $(OUTPUT)

clean:
	rm -rf $(BIN)/*
	rm analyelf.out

$(OUTPUT): $(OBJS)
	$(CC) $(FLAGS) $(OBJS) -o $(OUTPUT)

$(BIN)/%.o: $(SRC)/%.c $(HDRS)
	$(CC) $(FLAGS) -c $< -o $@

$(BIN)/section:
	mkdir $@

$(BIN)/cmd:
	mkdir $@
