from imporved_txt_to_json import parse_registers
from analyze_reg import analysis
from output_analysis import analyze_trace

def main():
    # run the work flow
    # Step 1: parse the registers in the json file
    file_name = './trace_data/improved_trace_exploited_vuln'
    parse_registers(file_name)
    # Step 2: analyze the registers for suspicious entries
    user_input = "A'*32 + 'B'*8 + '0x0000000000401176'"
    input_file_path = 'improved_trace_exploited_vuln.json'
    analysis(input_file_path)
    # Step 3: analyze the suspicious trace file using OpenAI API
    trace_file_path = "suspicious_registers_output.txt"
    result = analyze_trace(trace_file_path, user_input)
    print(result)

if __name__ == '__main__':
    main()
