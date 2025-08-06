# Custom Assembler

## Overview

This is a Python-based assembler for a customizable CPU architecture defined via JSON ISA definitions. It supports assembling programs with flexible operand types, instruction formats, and pseudo-instructions.

---

## Usage

```bash
python assembler.py program.asm isa_definition.json [options]
```

### Options

- `-d`  
  Generate an intermediate debug file showing each instruction step-by-step.

- `-s`  
  Manually specify memory size.

- `-m`  
  Split machine code output into multiple files by byte order (e.g., low-order byte in one file, high-order in another, etc). Each file holds its respective byte from the final machine code word — useful for hardware that loads ROMs by byte-lane.

---

## ISA Definition Format

The assembler expects a JSON file describing the ISA, including:

- **hardware**  
  - `arcitecture`: `"harvard"`, `"RISC"`, etc.  
  - `reg file size`: total number of general-purpose registers  
  - `inst size`: instruction size in address steps 
  - `address width`, `data width`: in bits

- **operand types**: regex, aliases, and bit sizes for different operand formats

- **opcodes**: map instruction names to numeric opcode values

- **pseudo instructions**: macro-expansions into real instructions

- **syntax templates**: define operand types (e.g., `reg`, `imm`, etc.)

- **syntax**: map instructions to their expected operand forms

- **encoding templates / encoding**: how each instruction is packed into bits

---

## Supported Directives

- `.def <name>, <operand>`  
  Assign a name to an operand (e.g., `.def SRC, r2`)

- `.byte <value>`  
  Insert a raw byte into memory

- `.org <address>`  
  Set current output address

- `.include <file>`  
  Include another file; labels in the included file are **visible to the parent only**

- `.start <address>`  
  Set program start address (written to `"start pointer addr"` if ISA defines it)

---

## Features

- ISA is fully JSON-defined, including syntax and encodings
- Pseudo-instruction expansion system
- Clean error messages with operand validation
- Indentation-based local label and scope system
- Output splitting for multi-ROM systems (`-m`)
- Optional debug output (`-d`)

---

## Example ISA Snippet

```json
{
  "hardware": {
    "arcitecture": ["harvard", "RISC"],
    "reg file size": 16,
    "inst size": 1,
    "address width": 16,
    "data width": 8
  },
  "operand types": {
    "reg": {
      "aliases": ["register", "reg"],
      "re": "r(\\d+)",
      "size": 4
    },
    "address": {
      "aliases": ["addr", "address"],
      "re": "\\$([+-]?(?:0x[0-9a-fA-F]+|0b[01]+|0o[0-7]+|\\d+))",
      "size": 16
    }
  },
  "opcodes": {
    "nop": 4,
    "mov": 11,
    "ldi": 11
  },
  "pseudo instructions": {
    "inc": ["addi {op1}, 1, {op1}"],
    "halt": ["HALT_:", "   jmp HALT_"]
  }
}
```

---

If you're reading this and want to contribute, test, or learn how to write an ISA — feel free to fork or open an issue!
