import time
import utils as ut
from pathlib import Path
import argparse 


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Assemble a program using a custom ISA.")
    parser.add_argument("program", type=Path, help="Path to the input program file")
    parser.add_argument("isa", type=Path, help="Path to the ISA definition file")
    parser.add_argument("-o", "--output", type=Path, help="Path for the output binary file")
    parser.add_argument("-s", "--size", default=None, type=int, help="the address width of the mem module")
    parser.add_argument("-m", "--multi", action="store_true", help="Enable multi-file output (only needed for multi-byte ISA instructions)")
    parser.add_argument("-d", "--debug", action="store_true", help="make a file with debug info")
    parser.add_argument("-f", "--format", type=str, default="bin", help= "what format the output file should have")
    parser.add_argument("-e", "--endian", type=str, default="big", help= "if the file is in binary then this is needed.")

    args = parser.parse_args()

    # Resolve all paths to absolute
    program_path: Path = args.program.resolve()
    isa_path = args.isa.resolve()
    output_path = args.output.resolve() if args.output else program_path.with_suffix("." + args.format)
    binary_size = args.size

    if not program_path.is_file():
        print(f"Program file not found: {args.program}")
        exit()
    if not isa_path.is_file():
        print(f"ISA file not found: {args.isa}")
        exit()

    start = time.time()
    ut.Assembler().run(program_path, isa_path, output_path, binary_size, args.multi, args.debug, args.endian)
    print(f"completed in {(time.time() - start):.4f}s")
    pass

