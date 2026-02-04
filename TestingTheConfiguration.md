# Testing the configuration

1. Run the following commands via PowerShell to download malware samples to the monitored C:\Users\*\Downloads directory:

       curl "https://raw.githubusercontent.com/wazuh/wazuh-documentation/refs/heads/4.14/resources/samples/mirai" -o   $env:USERPROFILE\Downloads\mirai
       curl "https://raw.githubusercontent.com/wazuh/wazuh-documentation/refs/heads/4.14/resources/samples/xbash" -o   $env:USERPROFILE\Downloads\xbash
       curl "https://raw.githubusercontent.com/wazuh/wazuh-documentation/refs/heads/4.14/resources/samples/webshell" -o $env:USERPROFILE\Downloads\webshell

2. You can visualize the alert data in the Wazuh dashboard. To do this, go to the Security events module and add the filter in the search bar to query the alerts.

       rule.groups:yara

As seen in the image, llma3.2 provides more context to the malicious file detected by YARA. Further insight, such as origin, attack vectors, and impact of the malicious file, can be seen in the yara.chatgpt_response field.

