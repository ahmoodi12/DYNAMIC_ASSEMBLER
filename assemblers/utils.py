import json
import math
from pathlib import Path
import string
from typing import NoReturn
from termcolor import colored
from dataclasses import dataclass, field
import re


digit = re.compile(r"([+-]?(?:0x[0-9a-fA-F]+|0b[01]+|0o[0-7]+|\d+))")
label = re.compile(r"\w+")
#operand = re.compile(fr"r\d+|{digit.pattern}|\${digit.pattern}|\w+")
Mnemonic = re.compile(r"\s*(\w+)")
txt_file = re.compile(r"\w+\.txt")
directive_syntax = {".func": [], ".start": ["address"], ".def": ["variable", "operand"], ".val": [["value", "list"]], ".org": ["address"], ".include": ["file"]}
dir_op_types = {
        "value": {
            "aliases": ["val", "value"],
            "re": "([+-]?(?:0x[0-9a-fA-F]+|0b[01]+|0o[0-7]+|\\d+))",
            "size": 16,
            "convertable": True
        },
        "address": {
            "aliases": ["addr", "address"],
            "re": "\\$([+-]?(?:0x[0-9a-fA-F]+|0b[01]+|0o[0-7]+|\\d+))",
            "size": 16,
            "convertable": True
        },
        "file": {
            "aliases": ["file", "filename"],
            "re": r'["\']?((?:[a-zA-Z]:)?(?:[/\\]\w+|\w+[/\\])*\w+\.\w+)["\']?',
            "convertable": False
        },
        "variable": {"aliases": ["var", "variable"], "re": "(\\w+)", "convertable": False},
        "list": {
            "aliases": ["lst", "list"],
            "re": r"\[(.*?)\]",
            "convertable": False
        }
        }

DEFAULT_OP_TYPES = {
    "value": {
            "aliases": ["val", "value"],
            "re": "([+-]?(?:0x[0-9a-fA-F]+|0b[01]+|0o[0-7]+|\\d+))",
            "size": 16,
            "convertable": True
        },
    "address": {
            "aliases": ["addr", "address"],
            "re": "\\$([+-]?(?:0x[0-9a-fA-F]+|0b[01]+|0o[0-7]+|\\d+))",
            "size": 16,
            "convertable": True
        },
    "relative address": {
            "aliases": ["rel addr", "relative address"],
            "re": "\\$([+-]?(?:0x[0-9a-fA-F]+|0b[01]+|0o[0-7]+|\\d+))",
            "size": 16,
            "convertable": True
        },
    "variable": {"aliases": ["var", "variable"], "re": "(\\w+)", "convertable": False}, 
}
ISA_KEYS = {
    "opcodes": ["opcodes", "instructions", "insts"],
    "syntax": [
        "syntax", "instruction syntax", "cpu syntax",
        "instruction_syntax", "cpu_syntax"
    ],
    "encoding": [
        "encoding", "instruction encodings", "encodings",
        "instruction_encodings"
    ],
    "hardware": [
        "hardware", "cpu config", "arch config",
        "cpu_config", "arch_config"
    ],
    "pseudo": [
        "pseudo instructions", "pseudo", "pseudo inst", "pseudo insts",
        "pseudo_instructions", "pseudo_inst", "pseudo_insts"
    ],
    "syntax temp": [
        "syntax temp", "syntax templates", "syn templates",
        "syntax_templates", "syn_templates"
    ],
    "encoding temp": [
        "encoding temp", "encoding templates", "enc templates",
        "encodings templates", "enc_templates", "encoding_templates",
        "encodings_templates", "enc temp", "enc_temp"
    ],
    "op types": [
        "op types", "operand types", "op_types", "operand_types"
    ]
}
HARDWARE_KEYS = {
    "reg file size": [
        "reg file size", "register file size", "reg_file_size", "register_file_size",
        "num registers", "num_regs", "registers"
    ],
    "addr step size": [
        "addr step size", "address step size", "addr_step_size", "address_step_size"
    ],
    "start pointer addr": [
        "start pointer addr", "start address", "start_ptr", "start_ptr_addr", "entry_point", "start_pointer_address"
    ],
    "IRQ pointer addr": [
        "irq pointer addr", "irq_ptr", "irq", "IRQ_pointer_addr", "irq_vector", "interrupt_vector"
    ],
    "architecture": [
        "arcitecture", "architecture", "cpu architecture", "arch", "arch_type"
    ],
    "address width": [
        "address width", "addr width", "address_bits", "addr_bits", "address size", "addr_size"
    ],
    "data width": [
        "data width", "data_width", "data bits", "data_bits", "data size", "data_size"
    ],
    "inst size": [
        "inst size", "instruction size", "inst_size", "instruction_size",
        "instruction_length", "inst_length"
    ]
}



required_isa_keys = ["op types", "hardware", "encoding", "syntax", ]
required_hw_keys = [
        "reg file size", "address width", "arcitecture",
        "addr step size", "data width", "inst size"
    ]

def smart_split(s):
    parts = []
    depth = 0
    current = []
    for ch in s:
        if ch in "[{(":
            depth += 1
        elif ch in "]})":
            depth -= 1
        if (ch == "," or ch.isspace()) and depth == 0:
            if current:
                parts.append("".join(current).strip())
                current = []
            continue
        current.append(ch)
    if current:
        parts.append("".join(current).strip())
    return parts

def find_largest(lst):
    "find largest number in the list"
    biggest = 0
    if not len(lst):
        return None
    for i, item in enumerate(lst):
        if isinstance(item, int) and item > biggest:
            biggest = item
    return [i, item] # type: ignore

def get_current_scope(all_labels: list[dict], indent_levl):
    scope_labels = {}
    for labels in all_labels[:min(len(all_labels), max(0, indent_levl) + 1)]:
        scope_labels |= labels
    return scope_labels

def expand_dict(org_dict: dict, sub_dicts: list[dict]) -> dict:
    for dict in sub_dicts:
        org_dict |= dict
    return org_dict

def from_base_to_int(num: str, base: str) -> int:
    return int(num, {"bin": 2, "hex": 16, "dec": 10, "oct": 8}[base])

def from_base_to_bin(num: str, base: str) -> str:
    intval = int(num, {"bin":2, "hex":16, "dec":10, "oct":8}[base])
    bits = { "bin": len(num), "hex": 4 * len(num), "oct": 3 * len(num), "dec": max(intval.bit_length(), 1)}[base]
    return format(intval, f'0{bits}b')

def convert_to_base(n: int, base_name: str) -> str:
    if base_name == "bin":
        return bin(n)[2:]
    elif base_name == "hex":
        return hex(n)[2:]
    elif base_name == "dec":
        return str(n)
    return ""
    
def get_indent_count(string) -> int:
    string = re.match(r"[ \t]+", string)
    return len(string.group().replace("\t", "    ")) if string is not None else 0

def find_str_in_list(lst:list[str], string):
    for i, item in enumerate(lst):
        if isinstance(item, str) and item.find(string) > -1:
            return i

def get_mnemonic(line):
    try:
        return Mnemonic.match(line).group(1).lower() # type: ignore
    except:
        return None

def print_addr_data_table(data_dict):
    # Sort by address
    for addr, data in sorted(data_dict.items()):
        print(f"{addr:04X}: {data:04X}")
    for addr, data in sorted(data_dict.items()):
        print(f"{data:04X}")

def string_to_ord_list(line: str) -> str:
    def replacer(match):
        s = match.group(2)
        # Decode all escape sequences like \n, \r, \t, \\, etc.
        s = bytes(s, "utf-8").decode("unicode_escape")
        # Convert each character to its ASCII/Unicode code and return as a string
        return str([ord(c) for c in s])
    
    # Replace all quoted strings in the line
    return re.sub(r"(['\"])(.*?)\1", replacer, line)

@dataclass
class Instruction:
    address: int
    mnemonic: str
    parsed_line: str
    org_line: str
    operands: list[str] = field(default_factory=list)
    opcode: str | None = None
    machine_code: str = "0"

    def debug_line(self) -> str:
        # Replace labels with their values
        resolved_line = self.parsed_line
        #for label, val in labels.items():
        #    if label in resolved_line:
        #        resolved_line = resolved_line.replace(label, hex(int(val[1:])))

        # Format the basic debug info
        debug_info = f"{self.address:05X}: {resolved_line}"
        debug_info += " " * max(3, 50 - len(debug_info))  # padding

        # Add detailed metadata
        debug_info += f"// machine code: {self.machine_code}, org line: {self.org_line.strip()}\n\n"

        return debug_info


@dataclass
class ParsedLine:
    line: str
    address: int
    indent_level: int
    line_nr: int
    pseudo: bool
    func_name: str | None = None 
    

@dataclass
class Function:
    name: str
    scope: int
    local_labels:  list[dict] = field(default_factory=list)

class Assembler:
    def run(self, program_file: Path, isa_file: Path, output_file: Path, mem_size: int, multi_mem, debug, endian_format):
        
        debug = program_file.with_suffix(".debug") if debug else None
        self.initialize(multi_mem, program_file, isa_file, debug)
        if output_file.suffix == ".bin":
            self.address_steps = math.ceil(self.hardware["inst size"]/8) 
        self.mem_size = (mem_size if mem_size is not None else 2**self.hardware["address width"])
        self.parse_program(self.mem_size)

        self.initialize(multi_mem, first= False)
        insts = self.assemble_program()
        inst_map = self.decode_insts(insts)
        rom_data_width = self.hardware["data width"]
        arch = self.hardware["architecture"][1].lower()
        sections = math.ceil(max(inst_map.values()).bit_length() / rom_data_width)
        mem_map = {}
        for addr, num in inst_map.items():
            if num.bit_length() > rom_data_width and arch == "cisc" or arch == "risc":
                parts = math.ceil(num.bit_length() / rom_data_width) if arch == "cisc" else sections
                for part_i in range(parts):
                    if endian_format == "little":
                        shift = part_i * rom_data_width
                    else:  # big endian
                        shift = (parts - part_i - 1) * rom_data_width
                    mem_map[addr + part_i] = (num >> shift) & ((1 << rom_data_width) - 1)
            elif arch == "cisc":
                mem_map[addr] = num

        for addr in mem_map.keys():
            if addr in self.vals:
                inst_line = next((inst.org_line for inst in insts if inst.address in range(addr, addr + self.address_steps)), '<unknown>')

                self.error(
            f"collision! the value '{self.vals[addr]}' or in ascii '{chr(self.vals[addr])}' and the instruction "
            f"'{inst_line.strip()}' share the same address of {hex(addr)}", line_s=inst_line)
        mem_map |= self.vals
        #print_addr_data_table(mem_map)

        if multi_mem:
            for i, Bytearray in enumerate(spread_dict_values(mem_map)):
                make_file(output_file.with_suffix(f"{i+1}{output_file.suffix}"), Bytearray, self.mem_size, endian_format)
            
        else:
            if not output_file.suffix == ".bin":
                self.address_steps = 0
            make_file(output_file, mem_map, self.mem_size, endian_format, data_size=self.address_steps) # pyright: ignore[reportArgumentType]
        
        if self.debug_file:
            with open(self.debug_file, "w") as file:
                instructions = [line.debug_line() for line in sorted(self.instructions, key=lambda inst: inst.address)]
                file.writelines(instructions)
                    
            print(f"created {self.debug_file.name}")


    def initialize(self, multi_mem, program_file: Path = Path(), isa_file: Path = Path(), debug_file: None | Path = None, first = True):
        global dir_op_types
        if first:
            self.isa_file = isa_file
            with open(isa_file, "r") as f: # type: ignore
                raw_isa: dict = json.load(f)

            self.current_file: Path = isa_file
            self.isa, self.hardware = self.load_isa(raw_isa)

            self.current_file = program_file
            with open(program_file, "r") as f: # type: ignore
                self.whole_program: str = f.read()

            if multi_mem:
                self.address_steps = 1
            elif self.hardware["architecture"][1].lower() == "risc":
                self.address_steps = self.hardware["addr step size"]
            else:
                self.address_steps = None

            dir_op_types |= self.isa["op types"]
            self.debug_file = debug_file
            self.multi_mem = multi_mem
            self.parsed_lines:list[ParsedLine] = []
            self.vals = {}
            self.labels = [{}]
            self.variables = {}
            self.original_lines = self.whole_program.splitlines()
            self.lines = self.original_lines[:]
            self.current_pseudo_lines = [0, None]
            self.start = None
            self.instructions:list[Instruction] = []
        self.address = None
        self.overlooked_part = []
        self.current_indent_level = 0  
        

    def parse_program(self, size):  
        self.mem_size = size
        prev_indent = 0  
        next_higher_indent = 0  
        multi_line_comment = None
        current_func = None
        got_warned_abt_func_behavior = next_is_func = False
        # 
        self.funcs:list[Function] = []

        # indent_levels: indents
        self.indents = [0]  

        for self.line_i, self.line in enumerate(self.lines):  
            if self.current_pseudo_lines[0] == 0:
                self.current_line_nr = len(self.overlooked_part)
                self.original_line = self.original_lines[self.current_line_nr]  

            # comment removing
            if multi_line_comment is not None:
                if not (m := re.search(r"\*/", self.line)):
                    if self.current_pseudo_lines[0] == 0:
                        self.overlooked_part.append(self.original_line) 
                    continue
                self.line = self.line[m.end():]

            multi_line_comment, self = remove_comment(self)

            if not self.line.strip(): # type: ignore
                if self.current_pseudo_lines[0] == 0:
                    self.overlooked_part.append(self.original_line)
                continue 
            
            # string conversion
            if not self.line.strip().startswith(".include"): # pyright: ignore[reportAttributeAccessIssue]
                self.line = string_to_ord_list(self.line) # pyright: ignore[reportArgumentType]

            # indents and labels
            current_indent = get_indent_count(self.line)
            
            if next_higher_indent and prev_indent >= current_indent:
                self.error("there should to be an indentation after a label.", self.line.strip(), f"{self.overlooked_part[-1]}\n{self.original_line}", warn = not next_is_func) # type: ignore
            
            if not next_higher_indent and current_indent > prev_indent: 
                self.error("indent increased unexpectedly.",  self.line.strip()[0], f"{self.overlooked_part[-1]}\n{self.original_line}", warn = True) # type: ignore
            
            next_higher_indent = False
            
            if all(current_indent > indent for indent in self.indents):
                self.indents.append(current_indent)
                self.labels.append({})

            if current_indent not in self.indents:
                self.error("indent amount does not match any other indent amount.", self.line.strip()[0]) # type: ignore

            self.current_indent_level = self.indents.index(current_indent)
            prev_indent = current_indent

            
            if current_func is not None and self.current_indent_level < current_func.scope: # pyright: ignore[reportOptionalMemberAccess]
                current_func.local_labels = self.labels[current_func.scope:]
                self.labels = self.labels[:current_func.scope]
                self.indents = self.indents[:current_func.scope]
                current_func = None
                
        
            mnemonic = 0
            # groups: 1 = dir, 2 = sep, 3 = params
            directive = re.match(r"\s*(\.\w+)(,|\s+)?(.+)?", self.line) # type: ignore
            # groups: 1 = full label, 2 = underscores
            label = re.match(r"\s*((__)?\w+):", self.line) # type: ignore
            
            if directive is not None:
                if directive.group(1) not in directive_syntax:
                    self.error("directive is not built in.", directive.group())
                else:
                    next_is_func = self.parse_directive(directive)  
                    self.line = ""
      
            elif label is not None:
                next_higher_indent = True     
                self.line = self.line.replace(label.group(0), "") # pyright: ignore[reportAttributeAccessIssue]

                if self.address >= self.mem_size: # pyright: ignore[reportOptionalOperand, reportOperatorIssue]
                    self.error(f"the label {label.group(1)} is outside of the addressing space.", label.group(1))

                if label.group(1) in self.variables:
                        self.error(f"the label at line {len(self.overlooked_part)} is overwritting a variable name.", label.group(1), warn=True)
                if label.group(1) in self.isa["syntax"]:
                    self.error(f"the label at line {len(self.overlooked_part)} is overwritting a instruction name.", label.group(1), warn=True)

                if self.address is None:
                        self.error("address hasn't been specified", self.line) # type: ignore

                if label.group(2) is not None:
                    if label.group(1) in self.labels[0]:
                        self.error(f"the global labels '{label.group(1)}' match eachother.", label.group(1), warn=True)
                    
                    self.labels[0][label.group(1)] = f"${self.address}"

                else:
                    if label.group(1) in get_current_scope(self.labels, self.current_indent_level):
                        self.error(f"the local labels '{label.group(1)}' match eachother.", label.group(1), warn=True)

                    self.labels[self.current_indent_level][label.group(1)] = f"${self.address}"
                
                if next_is_func:
                    current_func = Function(label.group(1), self.current_indent_level + 1)
                    self.funcs.append(current_func)
                    next_is_func = False

            # address calculation and final parsing
            mnemonic = get_mnemonic(self.line)
            if mnemonic is not None:
                if next_is_func and not got_warned_abt_func_behavior:
                    self.error("after a .func there should be the functions label, all instruction before that label will be treated as normal instructions and do not get included in the function.", self.original_line, warn=True)
                    got_warned_abt_func_behavior = True
                
                if self.address is None:
                    self.error("address hasn't been specified", self.line) # type: ignore
                
                if self.current_pseudo_lines[0] == 0:
                    self.overlooked_part.append(self.original_line)
                else:
                    self.current_pseudo_lines[0] -= 1 
                
                if mnemonic in self.isa.get("pseudo", []):
                    self.parse_pseudo_inst(self.line.strip()) # type: ignore

                else:
                    if self.address is not None and self.address >= size:
                        self.error("the address went outside of the addressing space.", self.line) # pyright: ignore[reportArgumentType]

                    self.parsed_lines.append(
                        ParsedLine(self.line.strip(),  #  # pyright: ignore[reportAttributeAccessIssue]
                                   self.address,  # pyright: ignore[reportArgumentType]
                                   self.current_indent_level, len(self.overlooked_part)-1,
                                   (self.current_pseudo_lines[0] > 0), getattr(current_func, "name", None))) # type: ignore                    

                self.calc_address(mnemonic)
                continue

            if self.current_pseudo_lines[0] == 0:
                self.overlooked_part.append(self.original_line)

        if multi_line_comment:
            self.error("unclosed multiline comment. anything after it will be ignored", "/*", multi_line_comment, warn=True)


    def assemble_program(self):
        for self.line_i, self.line in enumerate(self.parsed_lines):
            self.current_indent_level = self.line.indent_level
            self.current_line_nr = self.line.line_nr
            self.original_line = self.original_lines[self.line.line_nr]
            self.address = self.line.address
            colliding_line = next((line for line in self.parsed_lines if line.address == self.address and line != self.line), None)
            if colliding_line is not None:
                colliding_org_line = self.original_line[colliding_line.line_nr]
                self.error(f"collision! the {"instruction" if colliding_line.pseudo else "instructions"} '{self.original_line}' and {"the pseudo instruction" if colliding_line.pseudo else ""} '{colliding_org_line}' share the same address of {hex(self.address)}.", colliding_org_line, colliding_org_line)

            mnemonic: re.Match = get_mnemonic(self.line.line)                # type: ignore
        
            if mnemonic in self.isa["syntax"] and mnemonic not in self.isa.get("pseudo"):
                bin_ops = self.parse_operands(self.line.line, self.isa["syntax"][mnemonic], mnemonic)[1]
                
                self.instructions.append(Instruction(self.line.address, mnemonic, self.line.line, self.original_line, bin_ops, self.isa.get("opcodes", {}).get(mnemonic, None))) # type: ignore

            else:
                self.error("Unknown intruction.", mnemonic) # type: ignore
        
            if self.address is not None and self.address >= self.mem_size: # pyright: ignore[reportOperatorIssue]
                self.error("the program went outside of the addressing space.", self.original_line)

        if self.start is None and self.hardware.get("start pointer addr", "None") != "None":
            self.error("no '.start' directive was found.", non_program_error=True)
        
        #for inst in self.instructions:
           # if inst.address in self.vals:
                #self.error(f"Byte definition at address 0x{inst.address:X} overlaps with program code or instruction data. This may lead to undefined behavior.", inst.org_line, self.whole_program, warn=True)

        # TODO improve the irq and start pointer/vector handling 
        #if self.hardware.get("start pointer addr", None) != None:
        #    byte_count = math.ceil(self.hardware["address width"] / 8)
        #    for i in range(byte_count):
        #        self.vals[self.hardware["start pointer addr"]] = (self.start >> ((byte_count - 1 - i) * 8)) & 0xFF

        return self.instructions


    def get_variable(self, var):
        if var in self.variables:
            var = self.variables[var]
        if var in self.variables:
            var = self.get_variable(var)
        return var

    def calc_address(self, mnemonic = None, step_size = 0):
        if self.address_steps is None and not step_size:
            self.address += self.get_inst_byte_length(mnemonic)  # pyright: ignore[reportOperatorIssue]
        elif step_size:
            self.address += step_size # pyright: ignore[reportOperatorIssue]
        else:
            self.address += self.address_steps  # pyright: ignore[reportOperatorIssue]

    def get_inst_byte_length(self, mnemonic):
        total_length = 0

        if self.isa.get("pseudo instructions", None) is not None and mnemonic in self.isa["pseudo instructions"]:
            for line in self.isa["pseudo instructions"][mnemonic]:
                line_mnemonic = get_mnemonic(line)
                total_length += len(self.isa["encoding"][line_mnemonic]) + 1 if line_mnemonic not in self.isa["pseudo instructions"] else self.get_inst_byte_length(line_mnemonic)
            return total_length

        else:
            return len(self.isa["encoding"][mnemonic]) + 1


    def parse_directive(self, dir:re.Match):
        # TODO add more directives such as .word and .int
        dir_str = dir.group(1) 
        if dir_str not in directive_syntax:
            self.error("unknown directive.", dir_str)

        dir_syntax = directive_syntax[dir_str]
        ops = self.parse_dir_ops(dir.group(0), dir_syntax, dir_str, (dir_str != ".def"))    

        if dir_str == ".func":
            return True

        if dir_str == ".org":
            self.address = ops[0]
            return False

        if dir_str == ".start":
            if self.hardware.get("start pointer addr", "None") != "None":
                self.address = ops[0]
            else:
                self.error("this isa arcitecture does not have a start pointer so .start is ignored", dir_str, warn=True)
            if self.start is not None:
                self.error("can't define start twice.")
                
            self.start = self.address = ops[0]
            return False
        
        if dir_str == ".def":             
            if label.fullmatch(ops[0]) is None:
                self.error("Variable names can only use letters, numbers and underscores.", ops[0])
                
            if ops[0] in self.isa["syntax"]:
                self.error(f"{dir.group(0)} is redefining {self.isa["syntax"][ops[0]]}", ops[0], warn=True)
        
            self.variables[ops[0]] = ops[1]
            return False
            
        if dir_str == ".val":
            vals = ops
            vals = digit.findall(str(ops[0]))
            for num in vals:
                num = int(num, 0)
                if num >= 2**self.hardware["data width"]: 
                    self.error(f"the value {num} exceeds the size of {dir_op_types["value"]["size"]} bits. not allowed in the .val directive", str(ops[1]))
                if self.address is None:
                    self.error(f"address hasn't been set.", str(self.address))
                if self.address >= self.mem_size: # pyright: ignore[reportOptionalOperand]
                    self.error(f"directive went out of the addressing space of {hex(self.mem_size)}.", dir_str, warn=True)
                if self.address in self.vals:
                    self.error("the directive is overwritting anothers directives vals in mem.", dir_str)
                self.vals[self.address] = num
                self.calc_address(step_size=math.ceil(num.bit_length()/self.hardware["data width"])) # pyright: ignore[reportAttributeAccessIssue, reportArgumentType]
            return False
        
        if dir_str == ".include":
            # Resolve the included file relative to the current program file
            included_file = Path(ops[0].strip('"'))

            if not included_file.is_absolute():
                included_file = self.current_file.parent / included_file

            if not included_file.is_file():
                self.error("Included file doesn't exist.", ops[0])

            # Create a temporary assembler for the included file
            temp_asm = Assembler()
            temp_asm.initialize(self.multi_mem, included_file, self.isa_file, self.debug_file)
            temp_asm.address = self.address
            temp_asm.parse_program(self.mem_size)

            # Merge labels, instructions, and variables from the included file
            self.labels[self.current_indent_level] |= temp_asm.labels[0]
            temp_asm.initialize(self.multi_mem, first=False)
            self.instructions += temp_asm.assemble_program()
            self.variables |= temp_asm.variables
            return False
        return False
    

    def parse_dir_ops(self, line:str, syntax, dir, change_ops):
        op_part = line[len(dir):]

        ops = smart_split(op_part)

        if len(syntax) != len(ops):
            self.error(f"'{dir}' expects {len(syntax)} operand(s), but got {len(ops)}.", )

        for i, exp_op_type in enumerate(syntax):
            ops[i] = self.parse_operand(ops[i], exp_op_type, dir_op_types, dir, change_ops)[0]
        
        return ops # pyright: ignore[reportReturnType]


    def parse_pseudo_inst(self, pseudo_line: str):
        mnemonic = get_mnemonic(pseudo_line) 
        op_part = pseudo_line[len(mnemonic):] # pyright: ignore[reportArgumentType]
    
        ops = smart_split(op_part)

        converted_lines: list[str] = self.isa["pseudo"][mnemonic]

        for line_i, line in enumerate(converted_lines):
            for i, op in enumerate(ops):
                line = line.replace("{" + f"op{i+1}" + "}", op) # type: ignore

            self.lines.insert(line_i + self.line_i + 1, (" " * self.indents[self.current_indent_level] + line))
        if self.current_pseudo_lines[0] == 0:
            self.current_pseudo_lines = [len(converted_lines), self.line]
        else:
            self.current_pseudo_lines[0] += len(converted_lines)

        syntax = self.isa["syntax"][get_mnemonic(pseudo_line)]
        if isinstance(syntax, str):
            syntax = self.isa["syntax temp"][syntax]

        for i, part in enumerate(syntax):
            if part in DEFAULT_OP_TYPES["address"]["aliases"]:
                syntax[i] = [part, DEFAULT_OP_TYPES["variable"]["aliases"][0]]

        self.parse_operands(pseudo_line, syntax, mnemonic, False)  # type: ignore


    def parse_operands(self, line:str, syntax, mnemonic, change_ops = True) -> list[list]:
        op_part = line[len(mnemonic):]
        if isinstance(syntax, str):
            syntax = self.isa["syntax temp"][syntax]

        ops = smart_split(op_part)

        if len(syntax) != len(ops):
            self.error(f"'{mnemonic}' expects {len(syntax)} operand(s), but got {len(ops)}.", )

        op_types = []
        op_type = ""
        for i, exp_op_type in enumerate(syntax):
            ops[i], op_type = self.parse_operand(ops[i], exp_op_type, self.isa["op types"] | DEFAULT_OP_TYPES, mnemonic, change_ops)
            op_types.append(op_type)
        bin_ops = []
        if change_ops:
            for i, op in enumerate(ops):
                bin_ops.append(bin(op)[2:].zfill(op_types[i]["size"])) # pyright: ignore[reportArgumentType]
                
        return [ops, bin_ops]  # pyright: ignore[reportReturnType]


    def parse_operand(self, op, exp_op_types, available_types, mnemonic, change_op):
        # looks for variables first then global labels then local label
        org_op = op

        if isinstance(exp_op_types, str):
            exp_op_types = [exp_op_types]
        op = self.get_variable(op)

        scope = get_current_scope(self.labels, self.current_indent_level)
        if isinstance(self.line, ParsedLine) and self.line.func_name:
            func = next((func for func in self.funcs if func.scope <= self.current_indent_level and func.name == self.line.func_name))
            scope = expand_dict(scope, func.local_labels)

        for exp_op_type in exp_op_types:
            if exp_op_type in available_types.get("relative address", {}).get("aliases", []):
                if op in scope:
                    addr = scope[op]
                    m = re.match(DEFAULT_OP_TYPES["address"]["re"], addr)
                    if not m:
                        self.error(f"Label '{op}' does not contain a valid address.", org_op)
                    op = "$" + str(int(m.group(1), 0) - self.address) # pyright: ignore[reportOperatorIssue]
                
        op = scope.get(op, op)

        if isinstance(op, str):
            op = op.lower()
        try:             
            op_type, op_match = self.get_op_type((op), available_types)
            op_type_aliases: list = op_type["aliases"] # pyright: ignore[reportArgumentType, reportCallIssue]
            expected = False
            exp_op_type = "none"
            for exp_op_type in exp_op_types:
                if exp_op_type in ["op", "operand"] or exp_op_type in op_type_aliases:
                    expected = True
            
            if not expected:
                self.error(f"Expected operand type '{exp_op_type}', but got '{op_type_aliases}' for operand '{org_op}'", org_op)
            if change_op and op_type["convertable"]: # type: ignore
                op = int(op_match.group(1), 0)

        except IndexError:
            self.error(f"Regex for operand type '{exp_op_type}' must capture a value in group(1).", op) # pyright: ignore[reportPossiblyUnboundVariable]
        except ValueError:
            self.error(f"couldn't convert the operand '{op}' to int, are you sure it's convertable?", op)
        
        return op, op_type # pyright: ignore[reportPossiblyUnboundVariable]

    def get_op_type(self, op: str, types: dict) -> tuple[list, re.Match] | NoReturn: # type: ignore
        for name, Type in types.items():
            if ((m := re.match(Type["re"], op)) and Type["re"]):
                if Type["convertable"] and int(m.group(1), 0) >= 2**Type["size"]:
                    self.error(f"operand '{op}' is outside of op type's '{name}' range.", op)
                return Type, m
        self.error(f"Unknown operand '{op}'.", op)
        
    
    def error(self, prompt, error_causing_part = "", line_s: str | None = None, non_program_error = False, warn = False):
        level_text = "Warning" if warn else "Error"
        colored_level = colored(level_text, ((255, 165, 0) if warn else "red"), attrs=["bold"])
        column = -1
        line_info = ""
        if not non_program_error:
            line_i = self.current_line_nr
            if line_s is None:
                line_s = self.whole_program.splitlines()[line_i]
            if self.current_pseudo_lines[0] or isinstance(self.line, ParsedLine) and self.line.pseudo:
                line_info += f" in pseudo instruction '{get_mnemonic(self.current_pseudo_lines[1])}'"
                line_s = f"pseudo definition:\n{self.isa['pseudo'][get_mnemonic(self.current_pseudo_lines[1])]}\n\nline:\n{line_s}"
                #self.current_file = self.isa_file
            
            line_info += f" at line {colored(line_i + 1, 'cyan')}"

            for line in line_s.split("\n"):
                if (column := line.find(error_causing_part)) > -1:
                    break
           
        colored_file = colored(self.current_file.name, "yellow", attrs=["underline"]) # type: ignore
        formatted_prompt = colored(f">>> {prompt} <<<", "blue")

        print(f"{colored_level} in the file {colored_file}{line_info};\n{formatted_prompt}\n")

        if line_s is not None:
            print(line_s)
        
        if not non_program_error and column > -1 and line_s is not None and not line_s.startswith("pseudo definition:"):
            print((" " * column) + colored("^" * len(error_causing_part), "red"))
        if not warn:
            exit()

    
    def load_isa(self, raw_isa):
        isa = {}

        # --- Normalize ISA keys using ISA_KEYS ---
        for token, aliases in ISA_KEYS.items():
            for alias in aliases:
                if alias in raw_isa:
                    isa[token] = raw_isa[alias]
                    break
            else:
                if token in required_isa_keys:
                    self.error(f"Missing required hardware key '{token}'", non_program_error=True)

        # --- Normalize hardware subkeys ---
        hw_raw = isa.get("hardware", {})
        hardware = {}
        for token, aliases in HARDWARE_KEYS.items():
            for alias in aliases:
                if alias in hw_raw:
                    hardware[token] = hw_raw[alias]
                    break
            else:
                if token in required_hw_keys:
                    self.error(f"Missing required hardware key '{token}'", non_program_error=True)

        isa["hardware"] = hardware

        # --- opcode validation ---
        opcodes = isa.get("opcodes", {})
        if not isinstance(opcodes, dict):
            self.error("opcodes must be a dictionary", non_program_error=True)
        for name, expansion in opcodes.items():
            if not isinstance(name, str):
                self.error(f"opcode name '{name}' must be a string", non_program_error=True)
            if not isinstance(expansion, str):
                self.error(f"opcode '{name}' be a binary str", non_program_error=True)

        # --- Syntax format validation ---
        syntax = isa["syntax"]
        if not isinstance(syntax, dict):
            self.error("Syntax must be a dictionary", non_program_error=True)
        for instr, ops in syntax.items():
            if isinstance(ops, list):
                if not all(isinstance(op, str) or isinstance(op, list) for op in ops):
                    self.error(f"Syntax for '{instr}' must be a list of strings or lists", non_program_error=True)

        # --- Pseudo instructions validation ---
        pseudo = isa.get("pseudo", {})
        if not isinstance(pseudo, dict):
            self.error("Pseudo instructions must be a dictionary", non_program_error=True)
        for name, expansion in pseudo.items():
            if not isinstance(name, str):
                self.error(f"Pseudo instruction name '{name}' must be a string", non_program_error=True)
            if not isinstance(expansion, list) or not all(isinstance(line, str) for line in expansion):
                self.error(f"Pseudo instruction '{name}' must expand to a list of strings", non_program_error=True)
            if name not in isa["syntax"]:
                self.error(f"Pseudo instruction '{name}' must have a syntax definition", non_program_error=True)
        
        # --- Encoding + template validation ---
        encoding = isa["encoding"]
        templates = isa.get("encoding temp", {})

        if not isinstance(encoding, dict):
            self.error("Encoding must be a dictionary", non_program_error=True)
        if not isinstance(templates, dict):
            self.error("Encoding templates must be a dictionary", non_program_error=True)

        inst_size = hardware["addr step size"]
        arc = hardware.get("arcitecture", ["", ""])[1] if isinstance(hardware.get("arcitecture"), list) else hardware.get("arcitecture", "")

        for instr, enc in encoding.items():
            if instr not in syntax:
                self.error(f"Encoding contains unknown instruction '{instr}'", non_program_error=True)

            if isinstance(enc, str):  # Template reference
                if enc not in templates:
                    self.error(f"Encoding template '{enc}' used by '{instr}' is not defined", non_program_error=True)
                template_enc = templates[enc]
                if not isinstance(template_enc, list) or not all(isinstance(e, str) for e in template_enc):
                    self.error(f"Encoding template '{enc}' must be a list of strings", non_program_error=True)
                #if arc == "RISC" and len(template_enc) != inst_size:
                    #self.error(f"Encoding template '{enc}' used by '{instr}' must be {inst_size} entries long for RISC", non_program_error=True)
            elif isinstance(enc, list):
                if not all(isinstance(e, str) for e in enc):
                    self.error(f"All parts of encoding for '{instr}' must be strings", non_program_error=True)
                if arc == "RISC" and len(enc) != inst_size:
                    self.error(f"Encoding for '{instr}' must be {inst_size} entries long for RISC", non_program_error=True)
            else:
                self.error(f"Encoding for '{instr}' must be a list or a template name string", non_program_error=True)

        return isa, isa["hardware"]

        
    def replace_term_in_encoding(self, match: re.Match, encoding_str: str, value_bin: str, bit_size: int) -> str:
        # 1 = start, 2 = end, 3 = single end
        start = int(match.group(1)) if match.group(1) and not match.group(3) else 0
        end = bit_size
        if match.group(2):
            end = match.group(2)
        if match.group(3):
            end = match.group(3)
        return encoding_str.replace(match.group(0), value_bin[start:end])


    def decode_insts(self, program: list[Instruction]) -> dict:
        encodings = {}

        for inst in program:
            encoding = self.isa["encoding"][inst.mnemonic]
            is_template = False

            if isinstance(encoding, str):
                encoding = self.isa["encoding temp"][encoding]
                is_template = True

            encoding_str: str = encoding[0].lower()

            # Replace opcode
            for match in re.finditer(r"'(?:(\d+)-(\d+)|(\d+))?\(opcode\)", encoding_str):
                if not inst.opcode:
                    self.error(f"no opcode for the inst '{inst.mnemonic}' was found.", non_program_error=True)
                encoding_str = self.replace_term_in_encoding(
                    match, encoding_str, inst.opcode, len(inst.opcode) # pyright: ignore[reportArgumentType]
                )
            if inst.opcode is None and re.search(r"\(opcode\)", encoding_str):
                self.current_file = self.isa_file
                self.error(f"found '(opcode)' in encoding but the instruction '{inst.mnemonic}' doesn't have a defined opcode.", non_program_error=True)

            # Replace operands
            syntax = self.isa["syntax"][inst.mnemonic]
            if isinstance(syntax, str):
                syntax = self.isa["syntax temp"][syntax]
            
            for op_i, op_type in enumerate(syntax):
                if op_i >= len(inst.operands):
                    self.error(f"op{op_i} is not one of the instructions '{inst.mnemonic}' operands.", non_program_error=True)

                op_value_bin = inst.operands[op_i]
                operand_pattern = fr"'(?:(\d+)-(\d+)|(\d+))?\(op{op_i+1}\)"
                found_match = False

                for match in re.finditer(operand_pattern, encoding_str):
                    encoding_str = self.replace_term_in_encoding(
                        match, encoding_str, op_value_bin, self.isa["operand sizes"][op_type]
                    )
                    found_match = True

                if not found_match and re.search(operand_pattern.replace("'", ""), encoding_str):
                    self.error(
                        f"the part '{encoding_str}' in the '{inst.mnemonic}' instruction "
                        f"{'encoding template' if is_template else 'encoding'} needs to have a quote (') at the start",
                        non_program_error=True
                    )

                # Replace letter placeholders (a, b, c, etc.)
                encoding_str = encoding_str.replace("_", "").lower()
                op_letter = string.ascii_lowercase[op_i]
                bit_count = encoding_str.count(op_letter)
                if bit_count:
                    encoding_str = encoding_str.replace(op_letter * bit_count, op_value_bin)
            
            # Finalize encoding
            encoding_str = encoding_str.replace("_", "").lower()
            if not encoding_str.isdecimal():
                self.error(f"the part '{encoding_str}' in the '{inst.mnemonic}' instructions {'encoding template' if is_template else 'encoding'} has too many operands", non_program_error=True)

            encoding_int = int(encoding_str, 2)

            encodings[inst.address] = encoding_int
            inst.machine_code = hex(encoding_int)

        return encodings


def remove_comment(self):
    multi = re.search(r"/\*", self.line)
    single = re.search(r"(//|#)", self.line)

    if multi is not None:
        self.line = self.line[:multi.start()]
        return self.original_line, self

    if single is not None:
        self.line = self.line[:single.start()]
    return None, self

def spread_dict_values(Dict: dict[int, int], ): 
    """spread the values in a dict across multiple dicts where each dict has one order of bytes from the values."""
    files_bytes = [{} for n in range(math.ceil(max(Dict.values()).bit_length()/8))]
    for addr, num in Dict.items():
        for i, byte in enumerate(num.to_bytes((math.ceil(num.bit_length()/8)), "little")):
            files_bytes[i][addr] = byte 
    return files_bytes

def dict_value_into_bytes(data: dict[int, int], data_byte_size: int = 0, endian: str = "big") -> dict[int, int]:
    result = {}
    if data_byte_size:
        for addr, num in data.items():
            for byte_i in range(data_byte_size):
                result[addr + byte_i] = (num >> (byte_i*8) if endian == "little" else num >> ((data_byte_size-byte_i-1)*8)) & 0xff
    else:
        for addr, num in data.items():
            byte_array = num.to_bytes((num.bit_length() + 7) // 8 or 1, endian) # type: ignore
            for i, byte in enumerate(byte_array):
                result[addr + i] = byte
    return result


def make_file(filename: Path, mem_map: dict[int, int], size: int, endian, pad_num = 0, data_size = 1):
    if filename.suffix == ".bin":
        make_bin_file(filename, mem_map, size, endian, pad_num, data_size)
    elif filename.suffix == ".hex":
        make_hex_file(filename, mem_map)
    elif filename.suffix == ".lgsm":
        make_logisim_file(filename, mem_map, size, pad_num)
    else:
        print(f"the output file's '{filename}' suffix is not supported.")
    print(f"created {filename.name}")

def make_hex_file(filename: Path, memory_map):  # pad_value unused here but kept for compatibility
    data_bytes = []
    data_addresses = []

    # Collect bytes and their actual addresses (no gap filling)
    for addr in sorted(memory_map):
        data_bytes.append(memory_map[addr])
        data_addresses.append(addr)

    def encode_hex_record(address, values):
        checksum = (-sum([len(values), (address >> 8) & 0xFF, address & 0xFF, 0x00] + values)) & 0xFF
        return f":{len(values):02X}{address:04X}00{''.join(f'{b:02X}' for b in values)}{checksum:02X}"

    filename = filename.with_suffix(".hex")
    with open(filename, "w") as hex_file:
        i = 0
        while i < len(data_bytes):
            chunk = [data_bytes[i]]
            start_addr = data_addresses[i]
            j = i + 1
            while j < len(data_bytes) and data_addresses[j] == data_addresses[j - 1] + 1 and len(chunk) < 16:
                chunk.append(data_bytes[j])
                j += 1
            hex_file.write(encode_hex_record(start_addr, chunk) + "\n")
            i = j

        # End-of-file record
        hex_file.write(":00000001FF\n")

    
def make_bin_file(filename: Path, memory_map, size: int, endian, pad_num: int = 0, data_size = 0): # type: ignore
    prev_addr = -1  
    bytes_out = []
    filename: Path = Path(filename)
    memory_map = dict_value_into_bytes(memory_map, data_size, endian)
    for addr in sorted(memory_map):
        # Fill all addresses up to current one
        for _ in range((addr - prev_addr - 1)*max(1, data_size)):
            bytes_out.append(pad_num)

        bytes_out.append(memory_map[addr])
        prev_addr = addr

    # Pad to full memory size
    while len(bytes_out) < size:
        bytes_out.append(0)

    filename = filename.with_suffix(".bin")
    with open(filename, "wb") as bin_file:
        bin_file.write(bytearray(bytes_out))


def make_logisim_file(filename: Path, mem_map: dict[int, int], size: int, pad_num: int = 0): # type: ignore
    output_bytes = []
    prev_addr = -1

    # Fill memory bytes from sparse dict
    for addr in sorted(mem_map):
        # Fill gaps with pad_num
        for _ in range(addr - prev_addr - 1):
            output_bytes.append(pad_num)
        output_bytes.append(mem_map[addr])
        prev_addr = addr

    # Pad to full memory size
    while len(output_bytes) < size:
        output_bytes.append(pad_num)

    # Convert values to hex strings without 0x prefix
    output_bytes = [format(num, "x") for num in output_bytes]

    # Write to .lgsm file
    filename = filename.with_suffix(".lgsm")
    with open(filename, "w") as file:
        file.write("\n".join(output_bytes))
    
