#!/bin/bash
# Installs the Sample Transfer UI on the Proxmox host. Run as root from this folder:  bash install.sh
set -euo pipefail
cd "$(dirname "$0")"
apt-get install -y genisoimage jq >/dev/null
install -d -m 755 /opt/sample-transfer
install -m 755 app.py /opt/sample-transfer/app.py
install -d -m 700 /etc/sample-transfer
install -m 644 sample-transfer.service /etc/systemd/system/sample-transfer.service
if [ ! -f /etc/sample-transfer/config.json ]; then
  install -m 600 config.example.json /etc/sample-transfer/config.json
  echo "Created /etc/sample-transfer/config.json from the example. Edit bind and allowed_networks, then rerun this script."
  exit 0
fi
if [ ! -f /etc/sample-transfer/auth ]; then
  echo "Set the login for the web UI:"
  python3 /opt/sample-transfer/app.py --set-password
fi
systemctl daemon-reload
systemctl enable --now sample-transfer.service
systemctl restart sample-transfer.service
sleep 1
systemctl --no-pager --lines=5 status sample-transfer.service || true
IP=$(python3 -c 'import json,os;p="/etc/sample-transfer/config.json";c=json.load(open(p)) if os.path.exists(p) else {};print(c.get("bind","<proxmox-ip>"),c.get("port",8443))')
set -- $IP
echo
echo "Open https://$1:$2  (certificate warning is expected, same certificate as the Proxmox UI)"
