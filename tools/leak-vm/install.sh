#!/bin/bash
# Leak VM helpers: cases-open/-close, login starter, app menu entries, hide /cases from the desktop
# Run as the desktop user (analyst) from this folder: bash install.sh
set -e
cd "$(dirname "$0")"
UUID=$(grep -o 'by-uuid/[0-9a-f-]*' /usr/local/bin/cases-open 2>/dev/null | head -1 | cut -d/ -f2 || true)
[ -n "$UUID" ] || UUID=$(lsblk -nro UUID,FSTYPE | awk '$2=="crypto_LUKS"{print $1; exit}')
[ -n "$UUID" ] || { echo "no LUKS volume found"; exit 1; }
echo "LUKS UUID: $UUID"
sed "s/__UUID__/$UUID/" cases-open | sudo tee /usr/local/bin/cases-open >/dev/null
sudo install -m 755 cases-close cases-start cases-start-terminal cases-close-terminal /usr/local/bin/
sudo chmod 755 /usr/local/bin/cases-open
# do not offer the LUKS disk in the dock / Files (unlocking there mounts it in the wrong place)
echo "ENV{ID_FS_UUID}==\"$UUID\", ENV{UDISKS_IGNORE}=\"1\"" | sudo tee /etc/udev/rules.d/99-hide-cases.rules >/dev/null
sudo udevadm control --reload && sudo udevadm trigger --subsystem-match=block
mkdir -p ~/.local/share/applications ~/.config/autostart
install -m 644 cases-open.desktop cases-close.desktop ~/.local/share/applications/
install -m 644 cases-open.desktop ~/.config/autostart/cases-open.desktop
echo "Installed. At the next login a terminal asks for the passphrase and opens leak-hunter."
echo "App menu: 'Open cases' / 'Close cases' (can be pinned to the dock)."
