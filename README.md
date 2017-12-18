# elf_analyzer

# Installation
Execute `make` in the root directory of this repository.
```
cd elf_analyzer
make
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
- seg list
- seg dump index(phdr) [hex|h|bin|b]
## section
### general
- sec list
- sec dump index(shdr) [hex|h|bin|b]
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
- `hex` is equivalent to `h`
- `bin` is equivalent to `b`

# Add your own command
Add your code and header file to `elf_analyzer/src/cmd` and `elf_analyzer/include/cmd` respectively. The header file must be specified in `elf_analyzer/include/analy_eval.h` file, and the "root-function" (ie. eval_(feature)) in `elf_analyzer/src/eval.c`. Following the existing commands' formats, describe your own command's specification in these files. Your code must expose the root-function to the global scope, so that it will be accessible for the compiler. The name of the command should follow the convention: eval_(feature)\_(sub-feature)_...