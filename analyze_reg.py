import json
import re

def load_json(file_path):
    with open(file_path, 'r') as f:
        return json.load(f)

def contains_pattern(value, pattern_bytes):
    # Remove '0x' prefix and make uppercase
    value_hex = value[2:].upper()
    pattern_hex = ''.join(f'{byte:02X}' for byte in pattern_bytes)
    return pattern_hex in value_hex

def analyze_registers(register_dumps, pattern_bytes, address_bytes):
    suspicious_entries = []

    for idx, dump in enumerate(register_dumps):
        for reg, reg_info in dump.items():
            # Check register value
            if pattern_bytes: 
                value = reg_info.get('value', '')
                if value and value != '0x0000000000000000':
                    if (pattern_bytes and contains_pattern(value, pattern_bytes)) or (address_bytes and value.lower() == address_bytes):
                        suspicious_entries.append({
                            'index': idx,
                            'register': reg,
                            'field': 'value',
                            'value': value
                        })
            if address_bytes:
                # Check memory content
                memory_content = reg_info.get('memory_content', '')
                if memory_content:
                    if (pattern_bytes and contains_pattern(memory_content, pattern_bytes)) or (address_bytes and memory_content.lower() == address_bytes):
                        suspicious_entries.append({
                            'index': idx,
                            'register': reg,
                            'field': 'memory_content',
                            'value': memory_content
                        })

    return suspicious_entries

def analysis(input_file_path):

    register_dumps = load_json(input_file_path)
    
    # Patterns to look for
    pattern_bytes_A = [0x41] * 8  # 'A's
    pattern_bytes_B = [0x42] * 8  # 'B's
    address_bytes = '0x0000000000401176'.lower()

    # Analyze for 'A's
    suspicious_entries_A = analyze_registers(register_dumps, pattern_bytes_A, '')
    # Analyze for 'B's
    suspicious_entries_B = analyze_registers(register_dumps, pattern_bytes_B, '')
    # Analyze for the address
    suspicious_entries_addr = analyze_registers(register_dumps, [], address_bytes)

    # Combine all suspicious entries
    suspicious_entries = suspicious_entries_A + suspicious_entries_B + suspicious_entries_addr

    # Separate entries with the specific address
    address_entries = [entry for entry in suspicious_entries if entry['value'].lower() == address_bytes]
    other_entries = [entry for entry in suspicious_entries if entry['value'].lower() != address_bytes]

    # Write the output to a file
    output_file = 'suspicious_registers_output.txt'
    with open(output_file, 'w') as f:
        if address_entries:
            f.write("Entries with address '0x0000000000401176':\n")
            for entry in address_entries:
                field = entry['field']  # Field can be 'value' or 'memory_content'
                f.write(f"Index {entry['index']}, Register {entry['register']}, Field {field}: {entry['value']}\n")
            f.write("\n")

        if other_entries:
            f.write("Other suspicious register values detected:\n")
            for entry in other_entries:
                field = entry['field']  # Field can be 'value' or 'memory_content'
                f.write(f"Index {entry['index']}, Register {entry['register']}, Field {field}: {entry['value']}\n")
        else:
            f.write("No other suspicious register values detected.\n")

    print(f"Suspicious entries have been written to '{output_file}'.")

