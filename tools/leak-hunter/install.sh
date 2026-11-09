#!/bin/bash
# Installs leak-hunter on the leak analysis VM (700). Run from this folder: bash install.sh
set -e
cd "$(dirname "$0")"
for t in 7z rg pdftotext readpst mdb-export; do command -v $t >/dev/null || echo "missing: $t (see docs/19)"; done
sudo install -d -m 755 /opt/leak-hunter
sudo install -m 755 app.py /opt/leak-hunter/app.py
sudo install -m 644 ui.html /opt/leak-hunter/ui.html
sudo install -m 644 leak-hunter.service /etc/systemd/system/leak-hunter.service
sudo systemctl daemon-reload
# start/stop together with the encrypted /cases volume (not at boot)
if ! grep -q leak-hunter /usr/local/bin/cases-open; then
  sudo sed -i 's|^echo "Cases open.*|sudo systemctl start leak-hunter\necho "Cases open. Datashare: http://localhost:8080  leak-hunter: http://localhost:8090"|' /usr/local/bin/cases-open
fi
if ! grep -q leak-hunter /usr/local/bin/cases-close; then
  sudo sed -i 's|^cd /$|sudo systemctl stop leak-hunter\ncd /|' /usr/local/bin/cases-close
fi
if mountpoint -q /cases; then
  mkdir -p /cases/datashare/docs /cases/leak-hunter
  sudo systemctl restart leak-hunter
  sleep 1; systemctl --no-pager --lines=3 status leak-hunter | head -5
  echo "leak-hunter: http://localhost:8090"
else
  echo "Installed. Run cases-open to start it."
fi
