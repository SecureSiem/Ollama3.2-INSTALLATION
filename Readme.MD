# Ollama on Ubuntu 22.04 (Systemd Service) Setup

This guide installs Ollama as a systemd service, stores models in /var/lib/ollama/models, and exposes the API on port 11434 for integrations (example: Wazuh).

# A. Install Ollama (System Service)
1) Install Ollama

        curl -fsSL https://ollama.com/install.sh | sh

2) Verify binary and service
which ollama
ollama --version
systemctl status ollama --no-pager


Expected binary location:

/usr/local/bin/ollama

3) Enable and start service
sudo systemctl enable --now ollama
systemctl status ollama --no-pager


✅ Expected: active (running)

B. Create Models Directory and Set Permissions

Ollama system service runs as the ollama user, so it must own the storage path.

sudo mkdir -p /var/lib/ollama/models
sudo chown -R ollama:ollama /var/lib/ollama
sudo chmod 750 /var/lib/ollama
sudo chmod 750 /var/lib/ollama/models


Verify:

sudo ls -ld /var/lib/ollama /var/lib/ollama/models


✅ Expected owner/group: ollama ollama

C. Configure Ollama Using systemd Override (Recommended)

This ensures:

API bind address is controlled (OLLAMA_HOST)

Models location is forced (OLLAMA_MODELS)

1) Create the drop-in override file (guaranteed method)

Important: this method guarantees the override exists at:
/etc/systemd/system/ollama.service.d/override.conf

sudo mkdir -p /etc/systemd/system/ollama.service.d

sudo tee /etc/systemd/system/ollama.service.d/override.conf >/dev/null <<'EOF'
[Service]
Environment="OLLAMA_HOST=0.0.0.0:11434"
Environment="OLLAMA_MODELS=/var/lib/ollama/models"
EOF

2) Apply changes
sudo systemctl daemon-reload
sudo systemctl restart ollama

3) Confirm override is applied
systemctl cat ollama
sudo systemctl show ollama --property=Environment --no-pager


✅ Expected: Environment contains OLLAMA_HOST=0.0.0.0:11434 and OLLAMA_MODELS=/var/lib/ollama/models

D. Fix if Service Fails (start-limit-hit)

If you see start-limit-hit or the service won’t start:

sudo systemctl reset-failed ollama
sudo systemctl start ollama
systemctl status ollama --no-pager


To see the real reason for failure:

sudo journalctl -u ollama -b --no-pager -n 200

E. Install Models

Pull a model (example: llama3.2):

sudo ollama pull llama3.2


Run model (auto-pulls if missing):

sudo ollama run llama3.2


Verify models:

sudo ollama list
sudo ollama show llama3.2

F. Verify Model Files on Disk
sudo find /var/lib/ollama/models -maxdepth 2 -type d -print
sudo du -sh /var/lib/ollama/models


Expected directories:

blobs/

manifests/

G. Verify Ollama API Access

List models via API:

curl http://127.0.0.1:11434/api/tags


Generate a response:

curl http://127.0.0.1:11434/api/generate \
  -d '{"model":"llama3.2","prompt":"hello"}'


Confirm port listening:

ss -tulnp | grep 11434

H. Security Notes (Important)
If Wazuh runs on the SAME host (recommended)

Bind to localhost only:

Edit override:

sudo nano /etc/systemd/system/ollama.service.d/override.conf


Set:

[Service]
Environment="OLLAMA_HOST=127.0.0.1:11434"
Environment="OLLAMA_MODELS=/var/lib/ollama/models"


Apply:

sudo systemctl daemon-reload
sudo systemctl restart ollama

If Wazuh runs on a REMOTE host

Keep 0.0.0.0:11434, but restrict access using firewall rules to only the Wazuh server IP.

I. Optional Cleanup: Remove Old Duplicate Model Location

If you previously pulled models before setting OLLAMA_MODELS, you may have duplicate storage under:
/usr/share/ollama/.ollama/models

Check:

sudo find / -type d -name manifests -path "*ollama*" 2>/dev/null


If you confirm /var/lib/ollama/models is correct and contains your models, remove the old one:

sudo systemctl stop ollama
sudo rm -rf /usr/share/ollama/.ollama/models
sudo systemctl start ollama

Summary

Ollama installed as a systemd service

Service runs as ollama:ollama

Models stored in: /var/lib/ollama/models

API available at: http://<host>:11434

Suitable for Wazuh / SOC automation integrations
