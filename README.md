# DYNAMIC_ASSEMBLER

A simple yet powerful assembler that works with many CPU architectures by using an isa file or instruction set arcitecture file to define how it should assemble your assembly code.

If you build a cpu either in logisim or on a breadboard or in an emulator-then this tool helps you go ahead and write and assemble code for it.

---

## ✨ features

- supports wide variety of architectures that have an isa json defined for them. (might have bugs therefore i don't ensure it working for all the isa's)
  
- easy to read and clean syntax
  
- supports Windows, macOS, and various Linux x64-based distros

---

how it works:

Input:

- `.asm` file-your program
- `.json` isa file-the instruction set architecture
-  optional parameters like memory size -s (default is defined in the isa file), output filename -o (default is the program file name with .bin extension) and spreading the instructions across multiple bin files -m
  
The assembler reads the isa, parses your code, and spits out a binary file for you to load into your cpu.

if using multi mem the instruction is split up into bytes and every order of bytes goes into it's own bin file incase you need to spread the instruction, i find it useful in breadboarding where roms and flash mem usally only have 1 byte of data. here's an example:

let's say every instruction is 3 bytes
instructions  | bin file 1 | bin file 2 | bin file 3
instruction 1 | lowest        middle      highest   order bytes of the instruction encoding

i will be putting example files in the code files.
