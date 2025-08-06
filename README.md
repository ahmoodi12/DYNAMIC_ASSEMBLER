# Custom Assembler

## Overview

This is a Python-based assembler for a customizable CPU architecture defined via JSON ISA definitions. It supports assembling programs with flexible operand types, instruction formats, and pseudo-instructions.

---

## Usage

```bash
python {assembler.py} {program.asm} {isa_definition.json} [options]
Options
-d
Generate an intermediate debug file to help follow processor execution instruction-by-instruction.

-s
Manually specify memory size.

-m
Split instruction memory and data memory, allowing for multiple ROMs/RAMs (useful for hardware that has separate 8-bit ROM/RAM modules).

ISA Definition Format
The assembler expects a JSON file describing the ISA, including:

hardware: Architecture properties

arcitecture (e.g., "harvard", "RISC")

reg file size (e.g., 16 registers)

inst size (instruction size in bytes)

address width (bits)

data width (bits)

operand types: Regex patterns, aliases, and sizes for operand parsing
(e.g., register r\d+, immediate numbers, addresses)

opcodes: Mapping instruction names to opcode values.

pseudo instructions: Macro-like expansions into one or more base instructions.

syntax templates: Parameter types expected for each instruction form.

syntax: Instruction syntax mappings to templates.

encoding templates and encoding: Bit-level instruction encoding templates and instruction-specific encodings.

Supported Parser Directives
.def <name>, <operand>
Define a label or variable as an operand value (e.g., .def a, r1).

.byte <value>
Define a single byte of data in memory.

.org <address>
Set the address for the next instruction or data to be assembled at.

.include <file>
Include another source file; supports Python-style indent scoping. Included file labels are visible to the parent but not vice versa.

.start <address>
Marks the start address for execution. If your ISA JSON has "start pointer addr", this address is written there.

Features
Supports flexible operand types and syntax based on the ISA JSON file.

Supports pseudo-instructions which expand into multiple instructions.

Indentation-based scoping for included files and label visibility.

Intermediate debug output for step-by-step tracing.

Manual memory sizing and separate memory segmentation options.

Example ISA Snippet
json
Copy
Edit
{
  "hardware": {
    "arcitecture": ["harvard", "RISC"],
    "reg file size": 16,
    "inst size": 1,
    "address width": 16,
    "data width": 8
  },
  "operand types": {
    "reg": {"aliases": ["register", "reg"], "re": "r(\\d+)", "size": 4},
    "address": {"aliases": ["addr", "address"], "re": "\\$([+-]?(?:0x[0-9a-fA-F]+|0b[01]+|0o[0-7]+|\\d+))", "size": 16}
    // ...
  },
  "opcodes": {
    "nop": 4,
    "mov": 11,
    "ldi": 11,
    // ...
  },
  "pseudo instructions": {
    "inc": ["addi {op1}, 1, {op1}"],
    "halt": ["HALT_:", "   jmp HALT_"]
  },
  // ...
}
If you have any questions about features, usage, or ISA format, feel free to ask!
