import sys
import json
import subprocess
import os
import shutil
import logging
import Semgrep
from openai import OpenAI
from dotenv import load_dotenv
from typing import List

load_dotenv()

client = OpenAI(
    base_url="https://chat.science.ru.nl/api",
    api_key=os.environ["RAD_API_KEY"],
    timeout=120.0,
    max_retries=0,  
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Prompt templates
# TODO?: Copy less directly from the SAFE paper.
SYSTEM_TEMPLATE = """
You are an assistant with expertise in explaining
software security vulnerabilities in code snippets. You will
be given a code snippet and the result from Semgrep for the code snippet.

Your task is:
1. Analyze the "Code Context" and the specific "Vulnerable Snippet".
2. Explain the vulnerability using the Semgrep finding as a guide.
3. Determine why this specific pattern is dangerous in this context.

Provide your explanation by filling in the following template:
{template}
"""

USER_TEMPLATE = """
The code below was flagged by Semgrep. Explain the vulnerability detected in the code snippet to
a developer who has {level} experience in software security.

Semgrep Message: "{semgrep_message}"

Related CWEs: {cwe_id}

Here is the code to analyze:

Code Context (Surrounding lines):
{file_lines}

Vulnerable Snippet (Flagged lines):
{code_snippet}
"""

BASIC_TEMPLATE = """
- Vulnerability Type: 
- Severity: 
- Root cause:
- Suggested fix: [do not mention the message, describe it as if you suggested the fix]
"""

DETAILED_TEMPLATE = """
- Vulnerability Type: 
- Severity: 
- Root cause:
- Exploit scenario:
- Why it happens:
- Security implications:
- Suggested fix: [do not mention the message, describe it as if you suggested the fix]
"""


def call_LLM(system_prompt: str, user_prompt: str) -> str:
    try:
        model_name = "gemma4:31b"
        response = client.chat.completions.create(
            model=model_name,
            messages=[
                {
                    'role': 'system',
                    'content': system_prompt
                },
                {
                    'role': 'user',
                    'content': user_prompt
                }
            ],
            # -- This is optional for the output format --
            # response_format={
            #     "type": "json_schema",
            #     "json_schema": {
            #         "name": "json_file_name",
            #     },
            # },
            temperature=0.7,
        )
        
        return response.choices[0].message.content
        
    except Exception as e:
        logger.error(f"Error generating response: {str(e)}")
        return "Error generating explanation from AI."

def run_semgrep(target_file: str, config: str) -> List:
    # Using full path to the output file, otherwise it's safed somewhere else
    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_file = os.path.join(script_dir, "semgrep_temp_results.json")
    
    semgrep_executable = shutil.which("semgrep")
    if semgrep_executable is None:
        raise FileNotFoundError(
            "Semgrep was not found on PATH. Install it and ensure the semgrep "
            "command is available."
        )

    # Commands used to run Semgrep
    cmd = [
        semgrep_executable, "scan",
        f"--config={config}",
        "--verbose",
        "--no-git-ignore",
        "--json",
        "--output", output_file,
        target_file
    ]

    try:
        subprocess.run(cmd, capture_output=True, text=True)

        if not os.path.exists(output_file):
            return []

        with open(output_file, 'r') as f:
            data = json.load(f)      
        return data.get('results', [])
        
    except Exception as e:
        sys.stderr.write(f"Semgrep Error: {str(e)}\n")
        return []
    
def extract_code_context(base_path: str, relative_path: str, start_line: int, end_line: int) -> str:
    if os.path.isfile(base_path):
        file_to_open = base_path
    else: 
        file_to_open = os.path.join(base_path, relative_path)
    
    try: 
        with open(file_to_open, 'r', encoding='utf-8', errors='replace') as f: 
            lines = f.readlines()
        
        context_start = max(0, start_line - 5)
        context_end = min(len(lines), end_line + 2)
        return "".join(lines[context_start:context_end])
    except Exception: 
        return "Could not read source file."

if __name__ == "__main__":  
    if len(sys.argv) < 2:
        sys.exit(1)

    config = json.loads(os.environ.get("EXPLAINIFY_CONFIG", "{}"))

    semgrepConfig = config.get("semgrepConfig", "auto")
    level = config.get("level", "beginner")
    detailed = config.get("detailed", True)

    target_file_path = sys.argv[1]
    findings = run_semgrep(target_file_path, semgrepConfig)

    sm = Semgrep.Semgrep()
    sm.set_results()
    results_list = sm.result_list
    path_to_files = "java_files/"
    explanations = {}

    template = DETAILED_TEMPLATE if detailed else BASIC_TEMPLATE
    system_prompt = SYSTEM_TEMPLATE.format(template=template)

    # Looping through the results from Semgrep by file
    for file in results_list:
        with open(file, 'r', encoding='utf-8') as f: 
            all_lines = f.readlines()
        all_lines_final = "".join(all_lines)

        # Looping through the results of each file (each file can have multiple vulnerabilities)
        for finding in results_list[file]:
            start = finding['start_line']['line']
            end = finding['end_line']['line']
            code_snippet = extract_code_context(target_file_path, file, start, end)

            # Constructing the user and system prompts
            user_prompt = USER_TEMPLATE.format(
                semgrep_message=finding['message'],
                cwe_id=finding['vuln_ids'],
                file_lines=all_lines_final,
                code_snippet=code_snippet,
                level=level
            )
            
            # Calling the LLM
            explanation = call_LLM(system_prompt, user_prompt).lstrip()

            # This checks if the file name is already in the final results
            if file not in explanations:
                explanations[file] = []

            explanations[file].append(
                {
                    "line": start,
                    "endLine": end,
                    "message": finding['message'],
                    "ai_explanation": explanation,
                    "vulnerability": finding['vuln_ids']
                }
            )
    
    # Printing this ensures that the typescript file gets the explanations
    print(json.dumps(explanations, indent=2))
    sm.delete_semgrep_file()