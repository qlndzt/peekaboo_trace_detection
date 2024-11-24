from openai import OpenAI
import os

def analyze_trace(file_path, user_input):
    """
    Analyze the suspicious trace file for buffer overflow using OpenAI API.

    :param file_path: Path to the text file containing suspicious register outputs.
    :param user_input: User input used in the program.
    :return: Analysis result from OpenAI API.
    """
    # Read the content of the suspicious trace file
    if not os.path.exists(file_path):
        return "Error: File not found."

    with open(file_path, 'r') as file:
        trace_content = file.read()

    # Prepare the prompt for OpenAI API
    prompt = (
        "The following is the content of a suspicious trace file from a program. "
        "The user input provided was: \"" + user_input + "\". "
        "Analyze the trace and determine if a buffer overflow has occurred based on the input and register values. Output the conclusion first."
        "If a buffer overflow is detected, explain the evidence from the trace content.\n\n"
        "Trace Content:\n" + trace_content
    )
    client = OpenAI(
    api_key = os.getenv("OPENAI_API_KEY"),
    )
    try:
        completion = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You are a system security expert."},
            {
                "role": "user",
                "content": prompt
            }
        ])
        return completion.choices[0].message.content
    except Exception as e:
        return f"Error: {e}"

if __name__ == "__main__":
    # Path to the trace file
    trace_file_path = "suspicious_registers_output.txt"

    # Example user input
    user_input = "A'*32 + 'B'*8 + '0x0000000000401176'"

    # Analyze the trace file
    result = analyze_trace(trace_file_path, user_input)
    print(result)
