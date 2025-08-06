import json
import math
import os
from pathlib import Path
import string
from typing import NoReturn
from termcolor import colored
from dataclasses import dataclass, field
from collections import OrderedDict
import re


digit = re.compile(r"([+-]?(?:0x[0-9a-fA-F]+|0b[01]+|0o[0-7]+|\d+))")
label = re.compile(r"\w+")
#operand = re.compile(fr"r\d+|{digit.pattern}|\${digit.pattern}|\w+")
Mnemonic = re.compile(r"\s*(\w+)")
txt_file = re.compile(r"\w+\.txt")
builtin_directives = [".include", ".start", ".def", ".byte", ".org"]
directive_syntax = {".start": ["address"], ".def": ["variable", "operand"], ".byte": ["address", "value"], ".org": ["address"], ".include": ["variable"]}
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
        "encodings_templates"
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
    "inst size": [
        "instruction size", "inst size", "instruction_size", "inst_size", "word size", "word_size"
    ],
    "start pointer addr": [
        "start pointer addr", "start address", "start_ptr", "start_ptr_addr", "entry_point", "start_pointer_address"
    ],
    "IRQ pointer addr": [
        "irq pointer addr", "irq_ptr", "irq", "IRQ_pointer_addr", "irq_vector", "interrupt_vector"
    ],
    "arcitecture": [
        "arcitecture", "architecture", "cpu architecture", "arch", "arch_type"
    ],
    "address width": [
        "address width", "addr width", "address_bits", "addr_bits", "address size", "addr_size"
    ]
}


required_isa_keys = ["op types", "hardware", "encoding", "syntax", ]
required_hw_keys = [
        "reg file size", "address width", "arcitecture",
        "inst size"
    ]

def find_largest(lst):
    "find largest number in the list"
    biggest = 0
    if not len(lst):
        return None
    for i, item in enumerate(lst):
        if isinstance(item, int) and item > biggest:
            biggest = item
    return [i, item] # type: ignore

def get_current_scope(all_labels: list[dict], indent):
    scope_labels = {}
    for labels in all_labels[max(0, indent-1):]:
        scope_labels |= labels
    return scope_labels

def expand_dict(org_dict, sub_dicts):
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
    return Mnemonic.match(line).group(1).lower() # type: ignore

@dataclass
class Instruction:
    address: int
    mnemonic: str
    org_line: str
    operands: list[int] = field(default_factory=list)
    opcode: int | None = None

@dataclass
class ParsedLine:
    line: str
    address: int
    indent_level: int
    line_nr: int
    pseudo: bool

    def debug_line(self, indent, labels: dict[str, str]) -> str:
        line = self.line
        for label, val in labels.items():
            if label in line:
                line = line.replace(label, hex(int(val[1:])))
        debug_info = f"{self.address:05X}: {' ' * indent}{line}"
        debug_info += (" " * (70 - len(debug_info))) + f"// pseudo = {self.pseudo}\n"
        return debug_info


class Assembler:
    def run(self, program_file: Path, isa_file: Path, bin_filename: Path, bin_size: int, multi_mem, debug):
        debug = program_file.with_suffix(".debug") if debug else None
        self.initialize(multi_mem, program_file, isa_file, debug)
        self.parse_program()

        self.initialize(multi_mem, first= False)
        instructions = self.assemble_program()

        bin_size = (bin_size if bin_size else 2 ** self.hardware["address width"])
        if multi_mem:
            for i, Bytearray in enumerate(spread_dict_values(self.decode_insts(instructions))):
                make_bin_file(bin_filename.with_suffix(f"{i+1}.bin"), Bytearray, bin_size)
            
        else:
            #make_bin_file(bin_filename, dict_value_into_bytes(self.decode_insts(instructions)), bin_size)
            make_logisim_file(bin_filename, self.decode_insts(instructions), bin_size)


    def initialize(self, multi_mem, program_file: Path = Path(), isa_file: Path = Path(), debug_file: None | Path = None, first = True):
        if first:
            self.isa_file = isa_file
            with open(isa_file, "r") as f: # type: ignore
                raw_isa: dict = json.load(f)

            self.current_program_file: Path = isa_file
            self.isa, self.hardware = self.load_isa(raw_isa)

            self.current_program_file = program_file
            with open(program_file, "r") as f: # type: ignore
                self.whole_program: str = f.read()

            if multi_mem:
                self.address_steps = 1
            elif self.hardware["arcitecture"][1].lower() == "risc":
                self.address_steps = self.hardware["inst size"]
            else:
                self.address_steps = None

            self.debug_file = debug_file
            self.multi_mem = multi_mem
            self.parsed_lines:list[ParsedLine] = []
            self.bytes = {}
            self.local_labels = [{}]
            self.global_labels = {}
            self.variables = {}
            self.original_lines = self.lines = self.whole_program.splitlines()
            self.current_pseudo_lines = [0, None]
            self.start = None
        else:
            self.original_lines = self.whole_program.splitlines()

        self.instructions = []
        self.address = None
        self.overlooked_part = []
        self.current_indent_level = 0  
        
  
    def parse_program(self):  
        prev_indent = 0  
        next_higher_indent = 0  
        multi_line_comment = False

        # indent_levels: indents
        self.indents = {0: 0}  
        # indents: indent_level
        self.indent_levels = {0: 0}

        for self.line_i, self.line in enumerate(self.lines):  
            self.current_line_nr = len(self.overlooked_part)
            self.original_line = self.original_lines[self.line_i]  

            # comment removing
            if multi_line_comment:
                if not (m := re.search(r"\*/", self.line)):
                    self.overlooked_part.append(self.original_lines[self.line_i]) 
                    continue
                self.line = self.line[m.end():]

            multi_line_comment, self = remove_comment(self)

            if not self.line.strip(): # type: ignore
                self.overlooked_part.append(self.original_line)
                continue 
            
            # string conversion

            for match in re.finditer(r"(['\"])([\t\n\r -~])\1", self.line): # type: ignore
                self.line = self.line.replace(match.group(0), str(ord(match.group(2))))                 # type: ignore

            # indents and labels
            current_indent = get_indent_count(self.line)
            
            if next_higher_indent and prev_indent >= current_indent:
                self.error("there needs to be an indentation after a label.", self.line.split()[0], f"{self.overlooked_part[-1]}\n{self.original_line}") # type: ignore
            
            if not next_higher_indent and current_indent > prev_indent: 
                self.error("indent increased unexpectedly.",  self.line.strip()[0], f"{self.overlooked_part[-1]}\n{self.original_line}") # type: ignore
            
            next_higher_indent = False
            
            if all(current_indent > indent for indent in self.indent_levels.keys()):
                self.current_indent_level += 1
                self.indent_levels[current_indent] = self.current_indent_level
                self.indents[self.current_indent_level] = current_indent
                self.local_labels.append({})
            
            if current_indent not in self.indent_levels:
                self.error("indent amount does not match any other indent amount.", self.line.strip()[0]) # type: ignore

            else:
                self.current_indent_level = self.indent_levels[current_indent]
            
            prev_indent = current_indent


            mnemonic = 0
            # groups: 1 = dir, 2 = sep, 3 = params
            directive = re.match(r"\s*(\.\w+)(,|\s+)?(.+)?", self.line) # type: ignore
            # groups: 1 = full label, 2 = underscores, 3 = only letters
            label = re.match(r"\s*((__)?(\w+)):", self.line) # type: ignore

            if directive is not None:
                if directive.group(1) not in builtin_directives:
                    self.error("directive is not built in.", directive.group())
                else:
                    self.parse_directive(directive)  
      
            elif label is not None:
                next_higher_indent = True

                if self.address >= 2 ** self.hardware["address width"]:
                    self.error(f"the label {label.group(1)} (at address {self.address}) is outside of the addressing space.", label.group(1))

                if label.group(1) in self.variables:
                        self.error(f"the label at line {len(self.overlooked_part)} is overwritting a variable name.", label.group(1), warn=True)
                if label.group(1) in self.isa["syntax"]:
                    self.error(f"the label at line {len(self.overlooked_part)} is overwritting a instruction name.", label.group(1), warn=True)

                if self.address is None:
                        self.error("address hasn't been specified", self.line) # type: ignore

                if label.group(2) is not None:
                    self.global_labels[label.group(1)] = f"${self.address}"

                else:
                    if label.group(1) in get_current_scope(self.local_labels, self.current_indent_level):
                        self.error(f"the local labels '{label.group(1)}' match eachother.", label.group(1), warn=True)
                    
                    self.local_labels[self.current_indent_level][label.group(1)] = f"${self.address}"

            # address calculation and final parsing
            else:
                if self.address is None:
                    self.error("address hasn't been specified", self.line) # type: ignore
                
                mnemonic = get_mnemonic(self.line) # type: ignore

                if mnemonic in self.isa.get("pseudo", []):
                    self.parse_pseudo_inst(self.line.strip()) # type: ignore
                
                self.calc_pseudo()

                if mnemonic not in self.isa.get("pseudo", []):
                    self.parsed_lines.append(ParsedLine(self.line.strip(), self.address, self.current_indent_level, len(self.overlooked_part)-1, (self.current_pseudo_lines[0] > 0))) # type: ignore                    

                    self.calc_address(mnemonic)
            
            if mnemonic == 0:
                self.calc_pseudo()       

        if self.debug_file:
            with open(self.debug_file, "w") as file:
                for self.line in self.parsed_lines:
                    file.write(self.line.debug_line(self.indents[self.line.indent_level], expand_dict(self.global_labels, self.local_labels))) 

        if multi_line_comment:
            self.error("unclosed multiline comment. anything after it will be ignored", "/*", multi_line_comment, warn=True)


    def assemble_program(self):
        for line_i, line in enumerate(self.parsed_lines):
            self.current_indent_level = line.indent_level
            self.current_line_nr = line.line_nr
            self.original_line = self.original_lines[line.line_nr]

            mnemonic: re.Match = get_mnemonic(line.line)                # type: ignore
        
            if mnemonic in self.isa["syntax"] and mnemonic not in self.isa.get("pseudo"):
                ops = self.parse_operands(line.line, self.isa["syntax"][mnemonic], mnemonic)
                self.instructions.append(Instruction(line.address, mnemonic, self.original_line, ops,  self.isa.get("opcodes", {}).get(mnemonic, None))) # type: ignore

            else:
                self.error("Unknown intruction.", mnemonic) # type: ignore
        
            if self.address is not None and self.address >= 2**self.hardware["address width"]:
                self.error("the program went outside of the addressing space.", self.original_line)

        if self.start is None and self.hardware.get("start pointer addr", "None") != "None":
            self.error("no '.start' directive was found.", non_program_error=True)
        
        for inst in self.instructions:
            if inst.address in self.bytes:
                self.error(f"Byte definition at address 0x{inst.address[0]:X} overlaps with program code or instruction data. This may lead to undefined behavior.", inst.org_line, self.whole_program, warn=True)
         
        if self.hardware.get("start pointer addr", "None") != "None":
            byte_count = math.ceil(self.hardware["address width"] / 8)
            for i in range(byte_count):
                self.bytes[self.hardware["start pointer addr"] + i] = (self.start >> ((byte_count - 1 - i) * 8)) & 0xFF

        return self.instructions


    def get_variable(self, var, glob_label = False):
        if glob_label:
            if var in self.global_labels:
                var = self.global_labels[var]
            if var in self.global_labels:
                var = self.get_variable(var, glob_label)
            return var
        else:
            if var in self.variables:
                var = self.variables[var]
            if var in self.variables:
                var = self.get_variable(var)
            return var

    def calc_address(self, mnemonic):
        if self.address_steps is None:
            self.address += self.get_inst_byte_length(mnemonic) # type: ignore
        else:
            self.address += self.address_steps # type: ignore

    def get_inst_byte_length(self, mnemonic):
        total_length = 0

        if self.isa.get("pseudo instructions", None) is not None and mnemonic in self.isa["pseudo instructions"]:
            for line in self.isa["pseudo instructions"][mnemonic]:
                line_mnemonic = get_mnemonic(line)
                total_length += len(self.isa["encoding"][line_mnemonic]) + 1 if line_mnemonic not in self.isa["pseudo instructions"] else self.get_inst_byte_length(line_mnemonic)
            return total_length

        else:
            return len(self.isa["encoding"][mnemonic]) + 1

    def calc_pseudo(self):
        if not self.current_pseudo_lines[0]:
            self.overlooked_part.append(self.original_line)
        else:
            self.current_pseudo_lines[0] -= 1   


    def parse_directive(self, dir:re.Match):
        dir_str = dir.group(1)
        if dir_str in {".include", ".start", ".def", ".org", ".byte"} and dir.group(3) is None:
            self.error("directive needs argument(s).", dir_str)
        
        dir_syntax = directive_syntax[dir_str]

        #parameters = [op for op in self.parse_operands(dir.group(0), dir_syntax, dir_str, is_dir = True)] if dir_str != ".include" else [txt_file.search(dir.group(3)).group()] # type: ignore

        if dir_str != ".include":
            parameters = []
            for op in self.parse_operands(dir.group(0), dir_syntax, dir_str, (dir_str != ".def"), True):
                parameters.append(op)

        elif match := txt_file.search(dir.group(3)):
            parameters = [match.group()]
        else:
            parameters = []

        if dir_str == ".org":
            self.address = parameters[0]
            return

        if dir_str == ".start":
            if self.hardware.get("start pointer addr", "None") != "None":
                self.address = parameters[0]
            else:
                self.error("this isa arcitecture does not have a start pointer so .start is ignored", dir_str, warn=True)
            if self.start is not None:
                self.error("can't define start twice.")
                
            self.start = self.address = parameters[0]
            return
        
        if dir_str == ".def":             
            if label.fullmatch(parameters[0]) is None:
                self.error("Variable names can only use letters, numbers and underscores.", parameters[0])
                
            if parameters[0] in self.isa["syntax"]:
                self.error(f"{dir.group(0)} is redefining {self.isa["syntax"][parameters[0]]}", parameters[0], warn=True)
        
            self.variables[parameters[0]] = parameters[1]
            return
            
        if dir_str == ".byte":
            if parameters[1] > 255: # type: ignore
                self.error(f"the byte {parameters[1]} exceeds 8 bits.", parameters[1])

            if parameters[0] >= self.hardware["memory size"]:
                self.error(f"attempted to asign byte out of the addressing space.", parameters[0])
               
            self.bytes[parameters[0]] = parameters[1]
            return
        
        if dir_str == ".include":
            # TODO make the line update the indentation of included lines
            included_file = Path(parameters[0])
            if not included_file.is_file():
                self.error("included file doesn't exist.", parameters[0])

            temp_asm = Assembler()
            temp_asm.initialize(self.multi_mem, included_file, self.isa_file, self.debug_file)
            temp_asm.parse_program()
            self.parsed_lines += temp_asm.parsed_lines
            return


    def parse_pseudo_inst(self, pseudo_line: str):
        mnemonic = get_mnemonic(pseudo_line) 

        ops = self.parse_operands(pseudo_line, self.isa["syntax"][get_mnemonic(pseudo_line)], mnemonic, False)  # type: ignore
        
        converted_lines: list[str] = self.isa["pseudo"][mnemonic]

        for line_i, line in enumerate(converted_lines):
            for i, op in enumerate(ops):
                line = line.replace("{" + f"op{i+1}" + "}", op) # type: ignore

            self.lines.insert(line_i + line_i + 1, (" " * self.indents[self.current_indent_level] + line))
        if not self.current_pseudo_lines[0]:
            self.current_pseudo_lines = [len(converted_lines)+1, self.line]
            self.overlooked_part.append(self.original_line)
        else:
            self.current_pseudo_lines[0] += len(converted_lines)


    def parse_operands(self, line:str, syntax, mnemonic, change_ops = True, is_dir = False) -> list[int]:
        op_part = line[len(mnemonic):]
        if isinstance(syntax, str):
            syntax = self.isa["syntax temp"][syntax]

        ops = [op for op in re.split(r"(?:,\s*|\s+)", op_part) if op]

        if len(syntax) != len(ops):
            self.error(f"Instruction '{mnemonic}' expects {len(syntax)} operand(s), but got {len(ops)}.", )

        for i, exp_op_type in enumerate(syntax):
            ops[i] = self.parse_operand(ops[i], exp_op_type, is_dir, change_ops)
            
        return ops # type: ignore


    def parse_operand(self, op, exp_op_type, is_dir, change_op):
        # looks for variables first then global labels then local label
        op = self.get_variable(self.get_variable(op), True)

        op = get_current_scope(self.local_labels, self.current_indent_level).get(op, op)

        if isinstance(op, str):
            op = op.lower()
        try:
            op_type, op_match = self.get_op_type(op)

            if (op_type[0] not in ["var", "variable"]) and (exp_op_type not in ["op", "operand"] and (exp_op_type not in op_type)):
                self.error(f"Expected operand type '{exp_op_type}', but got '{op_type}' for operand '{op}'", op)
        
            if change_op:
                op = int(op_match.group(1), 0)
                return op

        except IndexError:
            self.error(f"Regex for operand type '{exp_op_type}' must capture a value in group(1).", op)
        except ValueError:
            if not is_dir:
                self.error(f"couldn't convert the operand '{op}' to int, possibly an unbound variable", op)
        
        return op
        
        
    def get_op_type(self, op: str) -> tuple[list, re.Match] | NoReturn: # type: ignore
        for name, Type in self.isa["op types"].items():
            if ((m := re.match(Type["re"], op)) and Type["re"]):
                if digit.match(m.group(1)) and int(m.group(1), 0) >= 2**Type["size"]:
                    self.error(f"operand '{op}' is outside of op type's '{name}' range.", op)
                return Type["aliases"], m
            
        self.error(f"Unknown operand '{op}'.", op)
        
    
    def error(self, prompt, error_causing_part = "", line_s: str | None = None, non_program_error = False, warn = False):
        level_text = "Warning" if warn else "Error"
        colored_level = colored(level_text, ((255, 165, 0) if warn else "red"), attrs=["bold"])
        column = -1
        if not non_program_error:
            line_i = self.current_line_nr
            if self.current_pseudo_lines[0] or isinstance(self.line, ParsedLine) and self.line.pseudo:
                line_info = f" in pseudo instruction '{get_mnemonic(self.current_pseudo_lines[1])}'"
                line_s = str(self.isa["pseudo instructions"][get_mnemonic(self.current_pseudo_lines[1])])
                self.current_program_file = self.isa_file
            else:
                line_info = f" at line {colored(line_i + 1, 'cyan')}"

            if line_s is None:
                line_s = self.whole_program.splitlines()[line_i]
                column = line_s.find(error_causing_part)
            else:
                for line in line_s.splitlines():
                    column = line.find(error_causing_part)
                    if column > -1:
                        break
        else:
            line_info = ""
        colored_file = colored(self.current_program_file.name, "yellow", attrs=["underline"]) # type: ignore
        formatted_prompt = colored(f">>> {prompt} <<<", "blue")

        print(f"{colored_level} in the file {colored_file}{line_info};\n{formatted_prompt}\n")

        if line_s is not None:
            print(line_s)
        
        if not non_program_error and column > -1:
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

        # --- Syntax format validation ---
        syntax = isa["syntax"]
        if not isinstance(syntax, dict):
            self.error("Syntax must be a dictionary", non_program_error=True)
        for instr, ops in syntax.items():
            if isinstance(ops, list):
                if not all(isinstance(op, str) for op in ops):
                    self.error(f"Syntax for '{instr}' must be a list of strings", non_program_error=True)
            elif not isinstance(ops, str):
                self.error(f"Syntax for '{instr}' must be a string or list of strings", non_program_error=True)

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

        inst_size = hardware["inst size"]
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
                if arc == "RISC" and len(template_enc) != inst_size:
                    self.error(f"Encoding template '{enc}' used by '{instr}' must be {inst_size} entries long for RISC", non_program_error=True)
            elif isinstance(enc, list):
                if not all(isinstance(e, str) for e in enc):
                    self.error(f"All parts of encoding for '{instr}' must be strings", non_program_error=True)
                if arc == "RISC" and len(enc) != inst_size:
                    self.error(f"Encoding for '{instr}' must be {inst_size} entries long for RISC", non_program_error=True)
            else:
                self.error(f"Encoding for '{instr}' must be a list or a template name string", non_program_error=True)

        return isa, isa["hardware"]

        
    def replace_term_in_encoding(self, pattern_match:re.Match, encoded_byte, value, val_bin_size) -> str:
        start = 0
        end = val_bin_size
        if pattern_match.group(1) is not None:
            start = int(pattern_match.group(1))
        
        if pattern_match.group(2) is not None:
            end = int(pattern_match.group(2))
        elif pattern_match.group(3) is not None:
            end = int(pattern_match.group(3))
        
        bits = end - start + 1
        mask = (1 << bits) - 1
        encoded_byte = encoded_byte.replace(pattern_match.group(0), f"{((value >> start) & mask):0{bits}b}")
        return encoded_byte

    def decode_insts(self, program: list[Instruction])->dict:
        encodings = {}
        for inst in program:
            template = False
            encoding = self.isa["encoding"][inst.mnemonic]
            if isinstance(encoding, str):
                encoding = self.isa["encoding temp"][encoding]
                template = True

            encoding: str = encoding[0]

            m = None
            # Groups: 1=start of range, 2=end of range, 3=single number; all None if no number/range
            for m in re.finditer(r"'(?:(\d+)\-(\d+)|(\d+))?\(opcode\)", encoding):
                encoding = self.replace_term_in_encoding(m, encoding, inst.opcode, self.isa["op types"]["opcode"]["size"])

                if inst.opcode is None and m is not None:
                    self.current_program_file = self.isa_file
                    self.error(f"found '(opcode) in encoding but the instruction '{inst.mnemonic}' doesn't have a defined opcode.", non_program_error=True)

            op_i = -1
            for op_i, type in enumerate(self.isa["syntax temp"].get(self.isa["syntax"][inst.mnemonic], self.isa["syntax"][inst.mnemonic])):
                op_value = inst.operands[op_i]  
                m: re.Match | None = None
                for m in re.finditer(fr"'(?:(\d+)\-(\d+)|(\d+))?\(op{op_i+1}\)", encoding):
                    encoding = self.replace_term_in_encoding(m, encoding, op_value, self.isa["operand sizes"][type])
                if m is None and re.search(fr"(?:(\d+)\-(\d+)|(\d+))?\(op{op_i+1}\)", encoding):
                        self.error(f"the part '{encoding}' in the '{inst.mnemonic}' instructions {'encoding template' if template else 'encoding'} needs to have a quote (this ' ) at the start", non_program_error=True)
            
                encoding = encoding.replace("_", "").lower()
                op_letter = string.ascii_lowercase[op_i]
                bits = encoding.count(op_letter)
                if bits:
                    encoding = encoding.replace(op_letter*bits, format(op_value, f"0{bits}b"))

                if op_i > len(inst.operands):
                    self.error(f"op{op_i} is not one of the instructions '{inst.mnemonic}' operands.", non_program_error=True) # type: ignore

            encoding = int(encoding, 2)  # type: ignore

            encodings[inst.address] = encoding

        return encodings

def remove_comment(self):
    multi = re.search(r"/\*", line) # type: ignore
    single = re.search(r"(//|#).*", line) # type: ignore
    if multi is not None:
        line = line[:multi.start()] # type: ignore
        return self.original_line, self
    if single is not None:
        line = line[:single.start()] # type: ignore
    return None, self

def spread_dict_values(Dict: dict[int, int], ): 
    """spread the values in a dict across multiple dicts where each dict has one order of bytes from the values."""
    files_bytes = [{} for n in range(math.ceil(max(Dict.values()).bit_length()/8))]
    for addr, num in Dict.items():
        for i, byte in enumerate(num.to_bytes((math.ceil(num.bit_length()/8)), "little")):
            files_bytes[i][addr] = byte 
    return files_bytes

def dict_value_into_bytes(data: dict[int, int], endian: str = "big") -> dict[int, int]:
    result = {}
    for addr, num in data.items():
        byte_array = num.to_bytes((num.bit_length() + 7) // 8 or 1, endian) # type: ignore
        for i, byte in enumerate(byte_array):
            result[addr + i] = byte
    return result


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

    print(f"created {filename.name}")

def make_bin_file(filename: Path, Bytearray, size: int, pad_num: int = 0): # type: ignore
    prev_addr = -1  # ← fix starts here
    bytes_out = []
    filename: Path = Path(filename)
    for addr in sorted(Bytearray):
        # Fill all addresses up to current one
        for _ in range(addr - prev_addr - 1):
            bytes_out.append(pad_num)

        bytes_out.append(Bytearray[addr])
        prev_addr = addr

    # Pad to full memory size
    while len(bytes_out) < size:
        bytes_out.append(0)

    filename = filename.with_suffix(".bin")
    with open(filename, "wb") as bin_file:
        bin_file.write(bytearray(bytes_out))

    print(f"created {filename.name}")

def make_logisim_file(filename:Path, memory_map, size, pad_num=0):  # type: ignore
    output_bytes = []
    prev_addr = -1

    # Fill memory bytes from sparse dict
    for addr in sorted(memory_map):
        for _ in range(addr - prev_addr - 1):
            output_bytes.append(pad_num)
        output_bytes.append(memory_map[addr])
        prev_addr = addr

    # Pad to full memory size
    while len(output_bytes) < size:
        output_bytes.append(pad_num)

    output_bytes = [hex(num)[2:] for num in output_bytes]

    filename = filename.with_suffix(".lgsm")
    with open(filename, "w") as file:
        file.write("\n".join(output_bytes))

    print(f"created {filename}")
