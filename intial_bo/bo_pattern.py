import json
from capstone import *
import re


with open('files/uaf_true.json', 'r') as f:
    data = json.load(f)

# Initialize Capstone disassembler for 64-bit x86
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True  

for entry in data:
    index = entry.get('index')
    address = int(entry.get('address'), 16)
    operation_str = entry.get('operation')
    registers = entry.get('registers')

    # Convert register values from hex strings to integers
    regs = {reg: int(value, 16) for reg, value in registers.items()}

    # Use regular expression to extract hex bytes at the beginning, handel the case for op code "0f 05     syscall brk (12)""
    match = re.match(r'^([0-9a-fA-F]{2}(?:\s+[0-9a-fA-F]{2})*)', operation_str.strip())
    if match:
        hex_str = match.group(1)
    else:
        print(f"No valid hex bytes found in operation at index {index}: {operation_str}")
        continue  # Skip this entry

    try:
        operation_bytes = bytes.fromhex(hex_str)
    except ValueError as e:
        print(f"Error parsing operation hex string at index {index}: {hex_str}")
        print(f"Exception: {e}")
        continue

    # Disassemble the operation bytes
    for insn in md.disasm(operation_bytes, address):
        # print(f"Instruction at 0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")

        # Check if the instruction writes to memory
        if insn.mnemonic.startswith('mov') and insn.operands:
            dest_op = insn.operands[0]

            # Check if the destination operand is memory
            if dest_op.type == CS_OP_MEM:
                mem = dest_op.mem
                base = mem.base
                index_reg = mem.index
                scale = mem.scale
                disp = mem.disp

                effective_address = 0

                if base != 0:
                    reg_name = insn.reg_name(base)
                    effective_address += regs.get(reg_name, 0)

                if index_reg != 0:
                    reg_name = insn.reg_name(index_reg)
                    effective_address += regs.get(reg_name, 0) * scale

                effective_address += disp

                #print(f"Memory write detected to effective address: 0x{effective_address:x}")

                # Detect potential buffer overflow
                # Assume buffer is allocated at rsp and has size 0x100
                buffer_start = regs['rsp']
                buffer_end = buffer_start + 0x100


                # information about the potential buffer overflow
                if effective_address < buffer_start or effective_address >= buffer_end:
                    print("Potential buffer overflow detected: write outside buffer bounds.")
                    print(f"Instruction at 0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
                    print(f"Effective Address: 0x{effective_address:x}")
                    print(f"Buffer Bounds: 0x{buffer_start:x} - 0x{buffer_end:x}")
                    print("Memory Operand Details:")
                    if base != 0:
                        base_reg_name = insn.reg_name(base)
                        base_reg_value = regs.get(base_reg_name, 'N/A')
                        print(f"  Base Register: {base_reg_name} = 0x{base_reg_value:x}")
                    if index_reg != 0:
                        index_reg_name = insn.reg_name(index_reg)
                        index_reg_value = regs.get(index_reg_name, 'N/A')
                        print(f"  Index Register: {index_reg_name} = 0x{index_reg_value:x}")
                        print(f"  Scale: {scale}")
                    print(f"  Displacement: {disp}")
                        
                    print("Potential buffer overflow detected: write outside buffer bounds.")
                # else:
                #     print("Memory write within buffer bounds.")

