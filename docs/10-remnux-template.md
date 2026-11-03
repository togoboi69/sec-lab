# 10 REMnux template

REMnux (Ubuntu 24.04 Noble) for email and document analysis, basic link and network analysis.

| VM | ID | Type |
|---|---|---|
| `remnux` | 9000 | Template |
| `remnux-work` | 301 | Linked clone, snapshot `clean` |

## Import (Proxmox shell)

REMnux ships as a ready-made Proxmox QCOW2 disk, not an installer ISO, so the import is done in the shell.

```bash
cd /var/lib/vz/images
wget https://download.remnux.org/202610b/remnux-noble-amd64-proxmox.qcow2
sha256sum remnux-noble-amd64-proxmox.qcow2
# expected: 9ef87306cd9b982de9109d08627040a15b2eb9d75040c9ceeffabce1a0004568

qm create 9000 --name remnux --ostype l26 --cores 2 --cpu host --memory 4096 \
  --scsihw virtio-scsi-single --net0 virtio,bridge=vmbr1 --vga std,clipboard=vnc --agent enabled=1
qm importdisk 9000 /var/lib/vz/images/remnux-noble-amd64-proxmox.qcow2 nvme
qm set 9000 --scsi0 nvme:vm-9000-disk-0,discard=on --boot order=scsi0
qm config 9000 | grep net0   # must be vmbr1
```

Check the download page for newer image versions and hashes before rebuilding.

Default login: auto-login, user `remnux`, password `malware` (changed).

## Display and clipboard

- Display: **Default** (std), Clipboard: **VNC**. With QXL/SPICE the Console button downloads `.vv` files instead of opening noVNC.
- Guest needs `spice-vdagent` (preinstalled).
- **Wayland breaks the clipboard.** Disable it: `/etc/gdm3/custom.conf` → `WaylandEnable=false`, reboot, `echo $XDG_SESSION_TYPE` must print `x11`.
- Use: noVNC side panel (arrow on left edge) → Clipboard box. Terminal copy/paste is Ctrl+Shift+C / Ctrl+Shift+V.

## Base config

- Keyboard: your layout via Settings → Keyboard (do it in the GUI first, a wrong layout garbles special characters when typing commands)
- `sudo timedatectl set-timezone <your timezone>`
- `passwd`
- Resolution: Settings → Displays, 1920x1080
- Update: `remnux install` (as user, not sudo), then reboot

## Tools

### EML Analyzer (Docker, local only)

```bash
sudo apt install -y docker.io && sudo usermod -aG docker remnux   # only if docker missing
sudo systemctl enable docker
docker run -d --name eml-analyzer --restart unless-stopped \
  -p 127.0.0.1:8000:8000 ghcr.io/ninoseki/eml_analyzer:latest
```

URL: http://localhost:8000. Optional env vars `VIRUSTOTAL_API_KEY`, `URLSCAN_API_KEY` (not set).

### CyberChef (offline copy)

Release assets are named `CyberChef_<commit-hash>.zip` (not `_v<version>`). REMnux's `~/.curlrc` sends a fake IE user-agent, so pass `-A "curl"` for the GitHub API.

```bash
mkdir -p ~/cyberchef && cd ~/cyberchef
curl -sL -A "curl" "$(curl -s -A "curl" https://api.github.com/repos/gchq/CyberChef/releases/latest \
  | grep -o 'https://[^"]*CyberChef_[^"]*\.zip' | head -1)" -o cc.zip
unzip -oq cc.zip && rm cc.zip && mv CyberChef_*.html CyberChef.html && ls
```

URL: file:///home/remnux/cyberchef/CyberChef.html

## Firefox policy (bookmarks and hardening)

`/etc/firefox/policies/policies.json`:

```json
{
  "policies": {
    "DisableTelemetry": true,
    "DisableFirefoxStudies": true,
    "DisablePocket": true,
    "DontCheckDefaultBrowser": true,
    "PasswordManagerEnabled": false,
    "OfferToSaveLogins": false,
    "DisableFormHistory": true,
    "PromptForDownloadLocation": true,
    "DisplayBookmarksToolbar": "always",
    "Homepage": { "URL": "about:blank", "StartPage": "none" },
    "Bookmarks": [
      { "Title": "VirusTotal", "URL": "https://www.virustotal.com/gui/home/search", "Placement": "toolbar", "Folder": "Intel" },
      { "Title": "AbuseIPDB", "URL": "https://www.abuseipdb.com/", "Placement": "toolbar", "Folder": "Intel" },
      { "Title": "Shodan", "URL": "https://www.shodan.io/", "Placement": "toolbar", "Folder": "Intel" },
      { "Title": "EML Analyzer", "URL": "http://localhost:8000/", "Placement": "toolbar", "Folder": "Tools" },
      { "Title": "CyberChef", "URL": "file:///home/remnux/cyberchef/CyberChef.html", "Placement": "toolbar", "Folder": "Tools" }
    ]
  }
}
```

Verify with `about:policies`. Add new template-wide bookmarks here. Bookmark your own sample source (e.g. a team file share) manually.

## Autostart

`~/bin/lab-start.sh`:

```bash
#!/bin/bash
docker start eml-analyzer >/dev/null 2>&1
for i in $(seq 1 30); do
  curl -s -o /dev/null http://127.0.0.1:8000/ && break
  sleep 2
done
firefox --new-window "http://localhost:8000/" --new-tab "file:///home/remnux/cyberchef/CyberChef.html" >/dev/null 2>&1 &
```

`~/.config/autostart/lab-start.desktop`:

```ini
[Desktop Entry]
Type=Application
Name=Lab tools
Exec=/home/remnux/bin/lab-start.sh
X-GNOME-Autostart-enabled=true
```


## Link analysis notes

- Inspect first without rendering: `curl -sIL <url>` (follows redirects, headers only).
- REMnux curl sends a fake IE user-agent by default. Compare with `-A "curl/8"` to spot UA-based cloaking.
- Egress is a Proton IP. Phishing kits often block VPN/datacenter IPs, so a "dead" link may still be live for victims.

## Convert to template

Inside the VM before converting:

```bash
history -c && rm -rf ~/Downloads/* ~/.cache/*
sudo truncate -s 0 /etc/machine-id && sudo rm -f /var/lib/dbus/machine-id \
  && sudo ln -s /etc/machine-id /var/lib/dbus/machine-id
sudo poweroff
```

Empty `machine-id` is required: otherwise every clone has the same DHCP identity and OPNsense hands two running clones the same IP.

Proxmox: VM 9000 → More → Convert to template.

## Clones and workflow

- Clone: right-click template → Clone, **Linked Clone**, storage `nvme`, IDs 301+.
- On each clone: snapshot `clean` right after first boot.
- Per case: work, then rollback to `clean`.
- Broken clone: delete, re-clone.
- Template change: see below.

## Updating the template

A template cannot be started, and it is the base disk of its linked clones, so never modify it in place. Rebuild it while keeping ID 9000:

1. Right-click 9000 → Clone → **Full Clone**, ID `302`, name `remnux-new`, storage `nvme`.
2. Start 302, make the changes, test (reboot).
3. Cleanup in 302 (history, cache, `machine-id`, see above), `sudo poweroff`.
4. Remove all linked clones of 9000 (e.g. 301), then remove 9000.
5. Right-click 302 → Clone → **Full Clone**, ID `9000`, name `remnux`. Convert 9000 to template. Remove 302.
6. New linked clone 301 `remnux-work`, test, snapshot `clean`.

If keeping ID 9000 does not matter, skip steps 4 and 5 and convert 302 directly.
