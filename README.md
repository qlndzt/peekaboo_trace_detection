# peekaboo_trace_detection

This repository provides a workflow for analyzing register traces from vulnerable programs to detect potential exploits such as buffer overflows. It processes raw trace data, identifies suspicious patterns in the registers, and utilizes the OpenAI API for further analysis.


## Workflow

1. **Parse Registers**:
   - Extract register dumps from the raw trace file and convert them into a structured JSON format.
2. **Analyze Registers**:
   - Detect suspicious patterns, such as repeated characters (e.g., `A` or `B`) or specific memory addresses.
3. **Trace Analysis**:
   - Utilize OpenAI's API to analyze the processed trace for evidence of exploits.

## File Structure

- `imporved_txt_to_json.py`: Parses raw trace files into JSON format.
- `analyze_reg.py`: Analyzes the parsed register data for suspicious patterns.
- `output_analysis.py`: Interfaces with the OpenAI API to analyze suspicious register traces.
- `initial_bo/`: Directory containing the original analysis function introduced in section ​​3
- `uaf/`: Directory containing the uaf analysis function introduced in section ​​3.5.3

## Installation

1. Clone this repository:
   ```bash
   git clone [<repository-url>](https://github.com/qlndzt/peekaboo_trace_detection.git)
   ```
2. Install required Python packages for main function:
   ```bash
   pip install openai
   ```
   Install required Python packages for intial_bo/ function:
   ```bash
   pip install capstone
   ```
4. Set up the OpenAI API key as an environment variable:
   ```bash
   export OPENAI_API_KEY="your-api-key"
   ```

## Usage

### Main Workflow
Run the `main.py` script to execute the workflow:
```bash
python main.py
```

### Input Files
- Place your raw trace file (e.g., `improved_trace_exploited_vuln.txt`) in the `trace_data/` directory.

### Output Files
- Parsed JSON file: `<input_file_name>.json`
- Suspicious register entries: `suspicious_registers_output.txt`
- OpenAI analysis result printed to the console.

## Example

### Input Trace File
Contents of `trace_data/improved_trace_exploited_vuln.txt`:
```
Registers and Memory Contents:
rip: 0x0000000000401176
...
```

### Command
```bash
python main.py
```

### Output
#### Console Output:
```plaintext
Parsed data has been written to improved_trace_exploited_vuln.json
Suspicious entries have been written to 'suspicious_registers_output.txt'
Trace analysis result: Buffer overflow detected...
```

#### Files Generated:
- `improved_trace_exploited_vuln.json`
- `suspicious_registers_output.txt`

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributing

Feel free to open issues or submit pull requests for improvements or bug fixes.

## Acknowledgments

Special thanks to OpenAI for providing the API used in this project.
