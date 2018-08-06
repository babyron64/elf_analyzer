CC=gcc
MAKE=make --no-print-directory
# DEBUGS=-g -O0

BIN=./bin
SRC=./src
INC=./include
BUILD=./build

SRCS=$(wildcard $(SRC)/*.c) $(wildcard $(SRC)/section/*.c) $(wildcard $(SRC)/cmd/*.c) $(wildcard $(SRC)/debug/*.c)
HDRS=$(wildcard $(INC)/*.h)
OBJS=$(patsubst $(SRC)/%.c, $(BIN)/%.o, $(SRCS))

SNIP_SRC=$(SRC)/snipets
SNIP_INC=$(INC)/snipets

SNIP_SRCS=$(wildcard $(SNIP_SRC)/*)
SNIPS=$(patsubst $(SNIP_SRC)/%, $(SNIP_INC)/%.sni, $(SNIP_SRCS))

FLAGS=-I $(INC) -I $(INC)/cmd -I $(SNIP_INC) -Wall $(DEBUGS)

OUTPUT=elf_analy.out
BIN_INSTALL_PATH=/usr/local/bin/elf_analy

.PHONY: all install uninstall clean count
# .PRECIOUS: $(SNIPS)

all: $(BIN)/section $(BIN)/cmd $(BIN)/debug $(BIN) $(OUTPUT)

install:
	cp $(OUTPUT) $(BIN_INSTALL_PATH)

uninstall:
	rm $(BIN_INSTALL_PATH)

clean:
	rm -rf $(BIN)/*

count:
	wc $(SRCS) $(HDRS)

$(OUTPUT): $(OBJS)
	$(CC) $(DEBUGS) $(FLAGS) $(OBJS) -o $(OUTPUT)

$(BIN)/%.o: $(SRC)/%.c $(HDRS) $(SNIPS)
	$(CC) $(DEBUGS) $(FLAGS) -c $< -o $@

$(SNIP_INC)/%.sni: $(SNIP_SRC)/%
	python3 $(BUILD)/mkIfElse.py $< $@ sni_value sni_name

$(BIN)/section:
	mkdir $@

$(BIN)/cmd:
	mkdir $@

$(BIN)/debug:
	mkdir $@
