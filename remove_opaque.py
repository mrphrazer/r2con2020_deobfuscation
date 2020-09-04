#!/usr/bin/python3
from z3 import *
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.ir.translators.z3_ir import TranslatorZ3

"""
based on Miasm commit 11f95aec61a5ab04d16e297164a9e7bc9434f786
"""


def branch_cannot_be_taken(expression, jump_target):
    # init solver
    solver = Solver()
    # init translator miasm ir -> z3
    translator = TranslatorZ3()
    # add constraint
    solver.add(translator.from_expr(expression) ==
               translator.from_expr(jump_target))
    # check for unsat
    return solver.check() == unsat


# hardcode file path and address
file_path = "samples/ac3e087e43be67bdc674747c665b46c2"
start_addr = 0x491aa0

# symbol table
loc_db = LocationDB()

# open the binary for analysis
container = Container.from_stream(open(file_path, 'rb'), loc_db)

# cpu abstraction
machine = Machine(container.arch)

# init disassemble engine
mdis = machine.dis_engine(container.bin_stream, loc_db=loc_db)

# initialize intermediate representation
ira = machine.ira(mdis.loc_db)

# disassemble the function at address
asm_cfg = mdis.dis_multiblock(start_addr)

# translate asm_cfg into ira_cfg
ira_cfg = ira.new_ircfg_from_asmcfg(asm_cfg)

# set opaque predicate counter
opaque_counter = 0

# dictionary of byte patches
patches = {}

# walk over all basic blocks
for basic_block in asm_cfg.blocks:
    # get address of first basic block instruction
    address = basic_block.lines[0].offset

    # init symbolic execution engine
    sb = SymbolicExecutionEngine(ira)

    # symbolically execute basic block
    e = sb.run_block_at(ira_cfg, address)

    # skip if no conditional jump
    if not e.is_cond():
        continue

    # cond ? src1 : src2

    # check if opaque predicate -- jump
    if branch_cannot_be_taken(e, e.src1):
        print(f"opaque predicate at {hex(address)} (jump is never taken)")
        opaque_counter += 1

        # get the jump instruction
        jump_instruction = basic_block.lines[-1]

        # get file offset from virtual address
        offset_of_jump_instruction = container.bin_stream.bin.virt2off(
            jump_instruction.offset)

        # walk over all instruction bytes and set corresponding file offsets to 0x90 (nop)
        for index in range(offset_of_jump_instruction, offset_of_jump_instruction + len(jump_instruction.b)):
            patches[index] = 0x90

    # check if opaque predicate -- fall-through
    elif branch_cannot_be_taken(e, e.src2):
        print(f"opaque predicate at {hex(address)} (always jump)")
        opaque_counter += 1


print(f"number of opaque predicates: {opaque_counter}")


print("patching")

# read raw bytes of file
raw_bytes = bytearray(open(file_path, 'rb').read())

# apply patches
for index, byte in patches.items():
    raw_bytes[index] = byte

# save patched file
open("samples/patched", 'wb').write(raw_bytes)
