import re
import json

def parse_registers(file_name):
    input_file_patj = file_name + '.txt'
    with open(input_file_patj, 'r') as f:
        content = f.read()

    # Split the content into blocks for each register dump
    blocks = content.split('Registers and Memory Contents:')
    parsed_data = []

    for block in blocks[1:]:  # Skip the first split which is before the first dump
        registers = {}
        lines = block.strip().split('\n')
        for line in lines:
            line = line.strip()
            if not line:
                continue
            # Match register lines
            match = re.match(r'^([a-zA-Z0-9]+):\s+([^\s]+)\s+->\s+Memory\[([^\]]+)\]:\s+(.*)$', line)
            if match:
                reg_name = match.group(1)
                value = match.group(2)
                mem_address = match.group(3)
                mem_content = match.group(4)
                registers[reg_name] = {
                    'value': value,
                    'memory_address': mem_address,
                    'memory_content': mem_content
                }
            else:
                # Handle registers without memory content like 'rflags' and 'rip'
                match_simple = re.match(r'^([a-zA-Z0-9]+):\s+([^\s]+)$', line)
                if match_simple:
                    reg_name = match_simple.group(1)
                    value = match_simple.group(2)
                    registers[reg_name] = {
                        'value': value
                    }
        parsed_data.append(registers)
    # Output the parsed data to a JSON file
    output_file_path = file_name + '.json'
    with open('improved_trace_normal_vuln.json', 'w') as json_file:
        json.dump(parsed_data, json_file, indent=4)

    print(f"Parsed data has been written to {output_file_path}")



def main():
    file_path = './trace_data/improved_trace_normal_vuln' 
    parse_registers(file_path)



if __name__ == '__main__':
    main()