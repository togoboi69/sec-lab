# 15 Kali VM (CTFs, hacking projects)

Persistent Kali Linux for CTFs (Hack The Box, TryHackMe), learning and experiments. Unlike the analysis VMs, this is a working VM: tools, notes and configs stay; snapshots protect against breakage.

## VM 600 `kali`

| Setting | Value |
|---|---|
| ISO | Kali installer, 64-bit (`kali-linux-2026.x-installer-amd64.iso` from kali.org/get-kali, Download from URL) |
| CPU / RAM | 4 cores host / 8192 MB |
| Disk | 80 GB on `nvme`, discard + SSD emulation |
| Network | `vmbr1`, VirtIO, firewall off: internet via Proton, blocked from home LAN and OPNsense |
| Display | Default, Clipboard VNC |
| Agent | QEMU guest agent on |

Installer: Graphical install, English, your location, your keyboard layout, guided partitioning (entire disk, one partition), Xfce + default tools, GRUB on `/dev/sda`.

Post-install:

```bash
sudo apt update && sudo apt full-upgrade -y
sudo apt install -y spice-vdagent qemu-guest-agent
sudo reboot
```

- Clipboard via noVNC side panel (Kali Xfce runs X11, so spice-vdagent works). Copy something in the VM first if pasting from outside does not work.
- Resolution: Settings → Display.
- Check: `ip -br a` (10.10.10.x), `curl -s ifconfig.me` (Proton IP).

## Usage

- CTF platforms: connect to their lab with their OpenVPN file inside Kali (runs inside the Proton tunnel).
- Snapshot before bigger changes; `clean-install` is the fallback.
- RAM budget: Proxmox ~2 GB + OPNsense 4 + Kasm 10 + Kali 8 ≈ 24 GB of 32. Do not run 401 and 402 (8 GB each) at the same time as well.

## Open

- [ ] Optional: isolated practice network (`vmbr3`, no internet) for vulnerable target VMs (e.g. Metasploitable), Kali with a second NIC there
