import json

def parse_first_line(line):
    # Trim any leading or trailing whitespace
    line = line.strip()
    
    # Extract the Instruction Index
    index_end = line.find(']')
    instruction_index = line[1:index_end].strip()
    
    # Extract the Memory Address and Operation Codes
    # Find the colon which ends the memory address
    colon_pos = line.find(':')
    memory_address = line[index_end+1:colon_pos].strip()
    
    # Everything after the colon is considered operation codes
    operation_codes = line[colon_pos+1:].strip()
    
    return instruction_index, memory_address, operation_codes


def parse_registers(lines):
    """ Parse register lines and return a dictionary. """
    registers = {}
    for line in lines:
        if ":" in line:
            key, value = line.split(":", 1)
            registers[key.strip()] = value.strip()
    return registers

def parse_instruction(block):
    """ Parse a single instruction block into a dictionary. """
    instruction = {}
    lines = block.strip().split('\n')
    
    # Extract the address and operation from the first line of the block
    if lines and ':' in lines[0]:
        instruction_index, memory_address, operation_codes = parse_first_line(lines[0])
        instruction['index'] = instruction_index
        instruction['address'] = memory_address
        instruction['operation'] = operation_codes

    # Memory operation parsing
    memory_line = next((line for line in lines if "Memory" in line), None)
    if memory_line:
        mem_type, mem_details = memory_line.split(': ', 1)
        instruction['memory_operation'] = {
            'type': mem_type.strip(),
            'details': mem_details.strip()
        }

    # Register information parsing
    registers_start = next((i for i, line in enumerate(lines) if line.strip().startswith("Registers:")), None)
    if registers_start is not None:
        instruction['registers'] = parse_registers(lines[registers_start + 1:])
    else:
        instruction['registers'] = {}

    return instruction

def parse_text_to_json(text):
    """ Parse the entire text into a structured JSON format. """
    instructions = []
    blocks = text.split('[')[1:]  # Split and remove the first chunk before the first instruction

    for block in blocks:
        block = '[' + block  # Add the split character back to each block
        if block.strip():
            instruction = parse_instruction(block)
            instructions.append(instruction)
            print(f"Processed instruction at {instruction.get('address', 'Unknown Address')} with operation {instruction.get('operation', 'No Operation')}")

    return instructions

def main():
    with open('uaf_true.txt', 'r') as file:
        text_data = file.read()

    instructions = parse_text_to_json(text_data)

    with open('uaf_true.json', 'w') as json_file:
        json.dump(instructions, json_file, indent=4)

    print("Successfully parsed the data and saved to 'buffer_overflow-error.json'.")

if __name__ == "__main__":
    main()
