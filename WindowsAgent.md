# Windows 11 endpoint

Perform the following steps to install Python, YARA, and download YARA rules.

1. Download the Python executable installer from the official Python website.

        https://www.python.org/downloads/windows/

2. Run the Python installer once downloaded, and make sure to check the following boxes:

        Install launcher for all users

  Add python.exe to PATH. This places the Python interpreter in the execution path.

3. Download and install the latest Visual C++ Redistributable package.

4. Open PowerShell with administrator privileges to download and extract YARA:

        Invoke-WebRequest -Uri https://github.com/VirusTotal/yara/releases/download/v4.5.1/yara-v4.5.1-2298-win64.zip -OutFile yara-v4.5.1-2298-win64.zip
        Expand-Archive yara-v4.5.1-2298-win64.zip; Remove-Item yara-v4.5.1-2298-win64.zip

5. Create a directory called C:\Program Files (x86)\ossec-agent\active-response\bin\yara\ and copy the YARA executable into it:

        mkdir 'C:\Program Files (x86)\ossec-agent\active-response\bin\yara\'
        cp .\yara-v4.5.1-2298-win64\yara64.exe 'C:\Program Files (x86)\ossec-agent\active-response\bin\yara\'

6. Download YARA rules using valhallaAPI. Valhalla is a YARA and Sigma rule repository provided by Nextron Systems:

        python -m pip install valhallaAPI
        python -c "from valhallaAPI.valhalla import ValhallaAPI; v = ValhallaAPI(api_key='1111111111111111111111111111111111111111111111111111111111111111'); response = v.get_rules_text(); open('yara_rules.yar', 'w').write(response)"
        mkdir 'C:\Program Files (x86)\ossec-agent\active-response\bin\yara\rules\'
        cp yara_rules.yar 'C:\Program Files (x86)\ossec-agent\active-response\bin\yara\rules\'

7. Create a script yara.py in the C:\Program Files (x86)\ossec-agent\active-response\bin\ directory. This script runs a YARA scan against any file modified or added to the monitored   directory. It also queries ollama3.2 to enrich the logs and attempts to remove malware files detected by YARA.
   replace <API_KEY> with your ollama URL key and <OLLAMA_MODEL> with your preferred OpenAI model. The model used in this POC guide is llama3.2:

        yara.py

8. Run the following command using PowerShell to convert the yara.py script to an executable file:

        pip install pyinstaller
        pyinstaller -F "C:\Program Files (x86)\ossec-agent\active-response\bin\yara.py"

NOTE:  If you run the above commands as Administrator, the executable file will be in the C:\Windows\System32\dist directory.

9. Copy the yara.exe executable file to C:\Program Files (x86)\ossec-agent\active-response\bin\ directory on the monitored endpoint.
10. Add the following within the <syscheck> block of the Wazuh agent C:\Program Files (x86)\ossec-agent\ossec.conf configuration file to monitor the Users directory:

        <directories realtime="yes">C:\Users\*\Downloads</directories>

11. Restart the Wazuh agent to apply the configuration changes:

        Restart-Service -Name wazuh
   
