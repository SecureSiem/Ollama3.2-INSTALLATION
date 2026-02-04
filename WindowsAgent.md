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
