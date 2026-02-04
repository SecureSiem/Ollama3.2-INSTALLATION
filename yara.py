import os
import subprocess
import json
import re
import requests

OLLAMA_MODEL = "llama3.2"
OLLAMA_URL = "http://192.168.1.61:11434/api/generate"

# Determine OS architecture and set log file path
if os.environ['PROCESSOR_ARCHITECTURE'].endswith('86'):
    log_file_path = os.path.join(
        os.environ['ProgramFiles'],
        'ossec-agent', 'active-response', 'active-responses.log'
    )
else:
    log_file_path = os.path.join(
        os.environ['ProgramFiles(x86)'],
        'ossec-agent', 'active-response', 'active-responses.log'
    )

def log_message(message):
    with open(log_file_path, 'a', encoding='utf-8', errors='ignore') as log_file:
        log_file.write(message + '\n')

def read_input():
    return input()

def get_syscheck_file_path(json_file_path):
    with open(json_file_path, 'r', encoding='utf-8', errors='ignore') as json_file:
        data = json.load(json_file)
        return data['parameters']['alert']['syscheck']['path']

def run_yara_scan(yara_exe_path, yara_rules_path, syscheck_file_path):
    try:
        result = subprocess.run(
            [yara_exe_path, '-m', yara_rules_path, syscheck_file_path],
            capture_output=True,
            text=True
        )
        out = (result.stdout or "").strip()
        return out if out else None
    except Exception as e:
        log_message(f"wazuh-YARA: ERROR - Error running YARA scan: {str(e)}")
        return None

def extract_description(yara_output):
    match = re.search(r'description="([^"]+)"', yara_output)
    return match.group(1) if match else None

def query_ollama(description):
    # IMPORTANT FIX:
    # Ask for a single paragraph and explicitly avoid markdown/newlines,
    # so Wazuh doesn't truncate the response.
    prompt = (
        "Explain this YARA detection in plain text only. "
        "Do not use markdown, bullet points, or new lines. "
        "In one short paragraph, include the threat summary, "
        "potential impact, and recommended mitigation. "
        f"Detection: {description}"
    )

    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.2
        }
    }

    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=30)
        if response.status_code == 200:
            text = response.json().get("response", "").strip()
            if not text:
                return None

            # CRITICAL FIX: force single-line output so Wazuh parses it fully
            single_line = " ".join(text.splitlines())
            single_line = re.sub(r"\s+", " ", single_line).strip()
            return single_line
        else:
            log_message(
                f"wazuh-YARA: ERROR - Ollama response {response.status_code}: {response.text}"
            )
            return None
    except Exception as e:
        log_message(f"wazuh-YARA: ERROR - Ollama connection failed: {str(e)}")
        return None

def main():
    json_file_path = r"C:\Program Files (x86)\ossec-agent\active-response\stdin.txt"
    yara_exe_path = r"C:\Program Files (x86)\ossec-agent\active-response\bin\yara\yara64.exe"
    yara_rules_path = r"C:\Program Files (x86)\ossec-agent\active-response\bin\yara\rules\yara_rules.yar"

    input_data = read_input()

    with open(json_file_path, 'w', encoding='utf-8', errors='ignore') as json_file:
        json_file.write(input_data)

    syscheck_file_path = get_syscheck_file_path(json_file_path)

    yara_output = run_yara_scan(yara_exe_path, yara_rules_path, syscheck_file_path)
    if not yara_output:
        log_message("wazuh-YARA: INFO - YARA scan returned no output.")
        return

    description = extract_description(yara_output)
    if not description:
        log_message("wazuh-YARA: INFO - Failed to extract description from YARA output.")
        return

    llm_response = query_ollama(description)

    # Optional: rename to 'chatgpt_response' to match Wazuh POC field naming
    combined_output = (
        f"wazuh-YARA: INFO - Scan result: {yara_output} | "
        f"chatgpt_response: {llm_response if llm_response else 'None'}"
    )
    log_message(combined_output)

    # Delete detected file
    try:
        os.remove(syscheck_file_path)
        if not os.path.exists(syscheck_file_path):
            log_message(f"wazuh-YARA: INFO - Successfully deleted {syscheck_file_path}")
        else:
            log_message(f"wazuh-YARA: INFO - Unable to delete {syscheck_file_path}")
    except Exception as e:
        log_message(f"wazuh-YARA: ERROR - Error deleting file: {str(e)}")

if __name__ == "__main__":
    main()
