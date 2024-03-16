# TMS320-Ghidra

Ghidra support for TMS320, in particular TMS320C32.

Very unfinished at this stage. Instruction decoding works (mostly) but there's no P-code for most instructions, so decompiling doesn't.

## Building

```bash

# Put this folder in /path/to/ghidra/Ghidra/Processors/

clang generate_opcodes.c -o generate_opcodes
./generate_opcodes > stage1-opcodes.txt

python3 process_opcodes.py

cp tms-autogen.sinc data/languages/

/path/to/ghidra/support/sleigh -a `pwd`

```