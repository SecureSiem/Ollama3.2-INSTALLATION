# Wazuh server
Perform the following steps on the Wazuh server to configure custom rules, decoders, and the Active Response module.

1. Add the following decoders to the Wazuh server /var/ossec/etc/decoders/local_decoder.xml file to parse the data in YARA scan result
