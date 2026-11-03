# 14 Kasm Workspaces

Disposable browser and desktop containers, streamed to the laptop browser. For quick link checks, phishing kits and OSINT. **Not for executing malware** (containers share the kernel; use 402 on vmbr2).

## Layout

```
Laptop <laptop IP> ──https://<OPN_WAN_IP>:8443──► OPNsense WAN (Destination NAT) ──► VM 500 kasm 10.10.10.20:8443 (vmbr1)
                                                                                         │
                                                                    Kasm sessions ───────┴──► internet via Proton
```

- Kasm VM on `vmbr1`: outbound via Proton, blocked from home LAN and OPNsense by the existing LAN rules.
- Laptop reaches only port 8443 through a port forward, only from the home LAN.

## VM 500 `kasm`

| Setting | Value |
|---|---|
| OS | Ubuntu Server 24.04.5 LTS (not 26.04: not confirmed supported by Kasm 1.19) |
| CPU / RAM | 4 cores host / 10240 MB, ballooning off |
| Disk | 120 GB on `nvme`, discard + SSD emulation; `ubuntu-lv` extended to full size in the installer (default uses only half) |
| Network | `vmbr1`, VirtIO, static `10.10.10.20/24`, gw and DNS `10.10.10.1` (outside DHCP range) |
| Extras | OpenSSH server, `qemu-guest-agent`, serial port 0 for xterm.js console |

ISO: `https://releases.ubuntu.com/24.04/ (live server ISO, latest 24.04.x)` (verify with `SHA256SUMS` in Proxmox "Download from URL").

### Console with copy/paste

noVNC clipboard does not work on a server without desktop. Use xterm.js instead:

1. In the VM once: `sudo systemctl enable serial-getty@ttyS0.service`
2. Proxmox: Hardware → Add → Serial Port 0, restart VM
3. Console dropdown → **xterm.js**; paste with right-click or Ctrl+Shift+V

`qemu-guest-agent` is a static unit on Ubuntu (starts automatically when the device exists); the `enable` warning is harmless.

## Kasm install

```bash
cd /tmp \
&& curl --fail-early -fO https://kasm-static-content.s3.amazonaws.com/kasm_release_1.19.0-latest.tar.gz \
                     -fO https://kasm-static-content.s3.amazonaws.com/kasm_release_1.19.0-latest.tar.gz.sha256sum \
&& sha256sum --check *.sha256sum \
&& tar -xf kasm_release_1.19.0-latest.tar.gz \
&& sudo bash kasm_release/install.sh -L 8443 -J 4096
```

- `-L 8443`: same port as the forward on OPNsense (443 is taken by the OPNsense GUI on WAN), avoids session connection issues with mismatched ports.
- `-J 4096`: creates 4 GB swap if none exists.
- Credentials for `admin@kasm.local` and `user@kasm.local` are printed once at the end; stored in the password manager.
- If the Docker image download breaks off (known tunnel issue), rerun the installer.

## OPNsense access

**Firewall → NAT → Destination NAT** (no associated filter rule is created in this view):

| Interface | Ver | Proto | Source | Destination | Port | Redirect target | Port | Description |
|---|---|---|---|---|---|---|---|---|
| WAN | IPv4 | TCP | WAN network | WAN address | 8443 | 10.10.10.20 | 8443 | Kasm UI |

**Firewall → Rules → WAN**, added manually (filter sees the translated destination):

| Action | Ver | Proto | Source | Destination | Port | Description |
|---|---|---|---|---|---|---|
| Pass | IPv4 | TCP | WAN network | 10.10.10.20 | 8443 | Kasm UI |

URL: **https://<OPN_WAN_IP>:8443**

The WAN live log shows blocked home LAN broadcast/multicast (router discovery, SSDP 239.255.255.250:1900, IGMP 224.0.0.22, Spotify 57621). Harmless, default deny.

## Workspaces and settings

Installed from **Workspaces → Registry**: Chrome, Firefox, Tor Browser. Kali workspace skipped (separate Kali VM planned).

Group **All Users** settings:

| Setting | Value | Reason |
|---|---|---|
| `allow_kasm_downloads` | False | Files from sessions never reach the laptop |
| `allow_kasm_uploads` | True | |
| `allow_kasm_clipboard_down` | True | Copy URLs/IOCs out |
| `allow_kasm_clipboard_up` | True | Paste links in |

Download/clipboard settings are per group/user, not per workspace. Workaround if ever needed: second user in a separate group with its own settings and workspace assignments. Files needed for analysis go through `remnux-work` (301) and the transfer UI instead.

Daily use with a normal user (not `admin@kasm.local`). Close sessions with **Delete Session**.

## Open

- [ ] Session limits (inactivity, max duration)
- [ ] Egress gateways (optional, skipped): only needed for per-session exit countries. Notes if ever done: one provider per country (Proton keys are per config), gateway config = Proton `.conf` without `PrivateKey`, plus `MTU = 1340` under `[Interface]` (tunnel inside tunnel), private key as egress credential on user or group, provider assigned on the workspace's Egress tab.
- [ ] Backup of Kasm config/database
