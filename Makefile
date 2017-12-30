CC=gcc
MAKE=make --no-print-directory

BIN=./bin
SRC=./src
INC=./include

SRCS=$(wildcard $(SRC)/*.c) $(wildcard $(SRC)/section/*.c) $(wildcard $(SRC)/cmd/*.c)
HDRS=$(wildcard $(INC)/*.h) $(wildcard $(INC)/cmd/*.h)
OBJS=$(patsubst $(SRC)/%.c, $(BIN)/%.o, $(SRCS))

FLAGS=-I $(INC) -I $(INC)/cmd -g -O0

OUTPUT=./bin/elf_analy.out
BIN_INSTALL_PATH=/usr/local/bin/elf_analy

.PHONY: all install uninstall clean

all: $(BIN) $(BIN)/section $(BIN)/cmd $(OUTPUT)

install:
	cp $(OUTPUT) $(BIN_INSTALL_PATH)

uninstall:
	rm $(BIN_INSTALL_PATH)

clean:
	rm -rf $(BIN)/*

$(OUTPUT): $(OBJS)
	$(CC) $(FLAGS) $(OBJS) -o $(OUTPUT)

$(BIN)/%.o: $(SRC)/%.c $(HDRS)
	$(CC) $(FLAGS) -c $< -o $@

$(BIN)/section:
	mkdir $@

$(BIN)/cmd:
	mkdir $@
