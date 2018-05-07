# elf_analyzer

# Installation
Execute `make` and `make install` in the root directory of this repository. You may need to execute `make install` with `sudo`.

```
cd elf_analyzer
make
sudo make install
```

# Usage
This analyzer works in two modes: single evaluation mode and multiple evaluation mode. For such a use as utilities in another program, you can use single evaluation mode. On the other hand, for manual analysis, you can use multiple evaluation mode.

## Single evaluation mode
Execute `elf_analy` with a file to analyze and arguments that indicate a command to evaluate:
```
elf_analy <filename> <command>
```
The commands available in default are shown later.

## Multiple evaluation mode
Execute `elf_analy` only with a file name:
```
elf_analy <filename>
```
This invokes an analyzer prompt: `(elf_analyzer)`. When prompt appears, enter a command and the analyzer evaluate it:
```
(elf_analyzer) <command>
```

# Command list
## header
### elf header
- ehdr
### program header
- phdr [show index(phdr)]
### section header
- shdr [show index(shdr)]
## segment
### general
- seg dump index(phdr) [hex|h|bin|b|ascii|asc|a]
## section
### general
- sec list
- sec dump index(shdr) [hex|h|bin|b|ascii|asc|a]
### string table
- str show index(shdr)
- str read index(shdr) index(strtbl)
### symbol table
- sym read index(shdr) index(symtbl)
### relocation without addends table
- rel read index(shdr) index(reltbl)
### relocation with addends table
- rela read index(shdr) index(relatbl)

---
- index(***): index of the entry in *** table(tbl)
- `h` is equivalent to `hex`
- `b` is equivalent to `bin`
- `a` is equivalent to `asc` and `ascii`

# Add your own command
Add your code and header file to `elf_analyzer/src/cmd` and `elf_analyzer/include/cmd` respectively. The header file must be specified in `elf_analyzer/include/analy_eval.h` file, and the "root-function" (ie. eval_(feature)) in `elf_analyzer/src/cmd.c`. Following the existing commands' formats, describe your own command's specification in these files. Your code must expose the root-function to the global scope, so that it will be accessible for the compiler. The name of the command should follow the convention: eval_(feature)\_(sub-feature)\_...
See the comments in src/cmd.c and src/cmd/ehdr_cmd.c files for more detailes.
