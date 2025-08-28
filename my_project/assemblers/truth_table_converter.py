import argparse
import re
from dataclasses import dataclass, field
from pathlib import Path
import time
from typing import NoReturn
from termcolor import colored
import utils as ut
from lark import Lark, Transformer

grammar = r"""
?start: expr

?expr: expr "+" term   -> or_expr
     | expr "^" term   -> xor_expr
     | term

?shift_expr: shift_expr "<<" term   -> lshift_expr
           | shift_expr ">>" term   -> rshift_expr
           | term

?term: term "&" factor -> and_expr
     | factor

?factor: "!" factor    -> not_expr
       | VAR
       | NUMBER
       | "(" expr ")"

VAR: /[a-z_]+/
NUMBER: /(_*\d+_*)+/

%ignore " "
"""

"""or, xor
          lsh, rsh
                  and 
                      not
                          parenthises"""

@dataclass
class EvalExpr(Transformer):
    output_base: str
    variables: dict = field(default_factory=dict)

    def or_expr(self, items):
        return format(int(items[0], 2) | int(items[1], 2), f'0{len(items[0])}b')

    def xor_expr(self, items):
        return format(int(items[0], 2) ^ int(items[1], 2), f'0{len(items[0])}b')

    def and_expr(self, items):
        return format(int(items[0], 2) & int(items[1], 2), f'0{len(items[0])}b')

    def lshift_expr(self, items):
        return format(int(items[0], 2) << int(items[1], 2), f'0{len(items[0])}b')
    
    def rshift_expr(self, items):
        return format(int(items[0], 2) >> int(items[1], 2), f'0{len(items[0])}b')

    def not_expr(self, items):
        length = len(items[0])
        result = (~int(items[0], 2)) & (2**length -1) 
        return format(result, f'0{length}b')
    
    def VAR(self, token):
        return self.variables[token]

    def NUMBER(self, token:str):
        return ut.from_base_to_bin(token.replace("_", ""), self.output_base)


# Create the parser
parser = Lark(grammar, start='start')

class TruthTableConverter:
    def convert(self, input_file: Path, output_file: Path, multi_mem, endian_format, rom_data_width, mem_size: int = 0) -> None:
        self.init(input_file)
        self.find_definitions()
        #out_bytes = ut.dict_value_into_bytes(self.parse_truth_table())
        mem_map = self.parse_truth_table()

        if not len(mem_map):
            self.error("there was no truth table in the input file")
        if not mem_size:
            mem_size = 2**(max(mem_map.keys())).bit_length() # type: ignore
            
        if multi_mem:
            for i, Bytearray in enumerate(ut.spread_dict_values(mem_map)):
                ut.make_file(output_file.with_suffix(f"{i+1}{output_file.suffix}"), Bytearray, mem_size, endian_format)
            
        else:
            ut.make_file(output_file, mem_map, mem_size, endian_format, data_size=rom_data_width) # pyright: ignore[reportArgumentType]


    
    def init(self, input_file: Path) -> None:
        self.input_file = input_file
        self.text = self.input_file.read_text().lower()
        self.lines = self.text.splitlines()
        self.line_i = 0
        self.current_program_file = self.input_file
        self.original_lines = self.lines.copy()

    def find_definitions(self) -> tuple[str, str, int]:
        self.output_base = ""
        self.input_base = ""
        self.size = None
        for self.line in self.lines:
            if not self.line or self.line.startswith("#"):
                continue
            if output_base_match := re.match(r"\s*(output_base|output|out)\s*=\s*(bin|hex|dec)", self.line):
                self.output_base = output_base_match.group(2)
            if input_base_match := re.match(r"\s*(input_base|input|in)\s*=\s*(bin|hex|dec)", self.line):
                self.input_base = input_base_match.group(2)
            if m := re.match(fr"\s*size\s*=\s*{ut.digit.pattern}", self.line):
                    self.size = int(m.group(1), 0)
            if self.output_base and self.input_base and self.size is not None:
                break
        if not self.output_base:
            self.error("Output base not specified", "output_base", exists_in_program=False)
        if not self.input_base:
            self.error("Input base not specified", "input_base", exists_in_program=False)
        if self.size is None:
            self.error("Size not specified so it will be calculated by the address width of the first element in the truth table.", "size", exists_in_program=False, warn=True)
        return self.input_base, self.output_base, self.size

    def parse_truth_table(self):
        multi_line_comment = False
        variable_names_defined = False
        variable_names = []
        variable_line_text = ""
        result_table = {}

        for self.line_i, self.line in enumerate(self.lines):
            self.original_line = self.original_lines[self.line_i]
            # Handle multi-line comments
            if multi_line_comment:
                end_comment = re.search(r"\*/", self.line)
                if not end_comment:
                    continue
                self.line = self.line[end_comment.end():]

            multi_line_comment, self = ut.remove_comment(self)
            if not self.line.strip():
                continue

            # Detect and extract variable names
            if not variable_names_defined and re.findall(r"\|\s*([a-z_]+)\s*", self.line):
                variable_names = re.findall(r"\|\s*([a-z_]+)\s*", self.line)
                variable_line_text = self.line
                variable_names_defined = True

            # Process truth table entries
            elif "->" in self.line:
                raw_inputs, raw_outputs = [
                    [token.strip() for token in section.split("|")]
                    for section in self.line.split("->", 1)
                ]
                raw_inputs =  [v.replace("_", "") for v in raw_inputs  if v]
                raw_outputs = [v for v in raw_outputs if v]

                parsed_output_expressions = [parser.parse(expr) for expr in raw_outputs]

                if len(raw_inputs) < len(variable_names):
                    self.error("Too many variables; any extras will be ignored", line_s=variable_line_text + "\n" + self.line, warn=True)

                for expanded_inputs in self.expand_wildcards(raw_inputs):
                    variables = {variable_names[i]: ut.from_base_to_bin(input_val, self.input_base)  for i, input_val in enumerate(expanded_inputs)} if variable_names else {}

                    output_values = []
                    evaluator = EvalExpr(self.output_base, variables)

                    for i, output_expr in enumerate(raw_outputs):
                        if re.fullmatch(r"[a-f\d_]+", output_expr) and self.output_base == "hex" or re.fullmatch(r"[10_]+", output_expr) and self.output_base == "bin" or re.fullmatch(r"[\d_]+", output_expr) and self.output_base == "dec":
                            output_values.append(ut.from_base_to_bin(output_expr.replace("_", ""), self.output_base))
                        else:
                            output_values.append(evaluator.transform(parsed_output_expressions[i]))

                    result_table[ut.from_base_to_int("".join(expanded_inputs), self.input_base)] = ut.from_base_to_int("".join(output_values), self.output_base)

        if multi_line_comment:
            self.error("Unclosed multiline comment. Anything after it will be ignored.", "/*", multi_line_comment, warn=True)

        return result_table

    def expand_wildcards(self, input: list[str]):
        expanded = []
        input_copy = input.copy()
        input_str = "".join(input)
        for i in range(2**input_str.count("x")):
            joined_input = input_str
            for char in bin(i)[2:].zfill(input_str.count("x")):
                joined_input = joined_input.replace("x", char, 1)

            seperated_input = []
            for input_section in input_copy:
                new_section = joined_input[:len(input_section)]
                seperated_input.append(new_section)
                joined_input = joined_input[len(input_section):]
            
            expanded.append(seperated_input)
        return expanded

    def error(self, prompt, error_causing_part = "", line_s: str | None = None, exists_in_program = True, warn = False) -> NoReturn: # type: ignore
        level_text = "Warning" if warn else "Error"
        colored_level = colored(level_text, ((255, 165, 0) if warn else "red"), attrs=["bold"])
        column = -1
        if exists_in_program:
            line_info = f" at line {colored(self.line_i + 1, 'cyan')}"

            if line_s is None:
                line_s = self.original_lines[self.line_i]
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
        
        if not exists_in_program and column > -1:
            print((" " * column) + colored("^" * len(error_causing_part), "red"))
        if not warn:
            exit()


if __name__ == "__main__":
    argparser = argparse.ArgumentParser(description="Assemble a program using a custom ISA.")
    argparser.add_argument("program", type=Path, help="Path to the input program file")
    argparser.add_argument("-o", "--output", type=Path, help="Path for the output binary file")
    argparser.add_argument("-s", "--size", default=None, type=int, help="the address width of the mem module")
    argparser.add_argument("-m", "--multi", action="store_true", help="Enable multi-file output (only needed for multi-byte ISA instructions)")
    argparser.add_argument("-f", "--format", type=str, default="bin", help= "what format the output file should have")
    argparser.add_argument("-e", "--endian", type=str, default="big", help= "if the file is in binary or logisim format then this is needed.")
    argparser.add_argument("-d", "--data_width", type=int, default=8, help= "the data width of the rom")

    args = argparser.parse_args()

    # Resolve all paths to absolute
    input_path: Path = args.program
    output_path = args.output.with_suffix("." + args.format) if args.output else input_path.with_suffix("." + args.format)
    binary_size = args.size

    if not input_path.is_file():
        print(f"Program file not found: {args.program}")
        exit()

    start = time.time()
    TruthTableConverter().convert(input_path, output_path, args.multi, args.endian, args.data_width, binary_size)
    print(f"completed in {(time.time() - start):.4f}s")
