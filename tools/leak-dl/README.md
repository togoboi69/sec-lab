# leak-dl: download VPS for leak data

Large leaks (tens to hundreds of GB) are downloaded on a **cloud server** (via Tor for `.onion`, directly for clearnet), then pulled into the leak VM over the home fibre connection.

```
Leak site ──Tor (.onion / --tor) or direct (clearnet)──► download VPS (Hetzner, project leak-dl)
                                           │  /data/out/<case>/ + SHA256SUMS
                                           │
              rsync over SSH, pulled by the leak VM (no inbound ports at home),
              key restricted to read-only rsync of /data/out (rrsync)
                                           │
OPNsense: only LEAK_VM → LEAK_VPS:22 via WAN, everything else stays in the VPN
                                           ▼
                    VM 700 /cases/datashare/docs/<case>/  (see docs/16) → leak-hunter
```

Why:

- Your home IP never touches the leak site: it sees a Tor exit (`.onion`, `--tor`) or the VPS IP (clearnet direct).
- `.onion` sites are only reachable via Tor. Clearnet hosts are downloaded **directly** by default: much faster, and the site only sees a cloud IP. Use `--tor` when the VPS IP should not be visible either (e.g. a host that logs and blocks downloaders, or attribution of the cloud account matters). Some clearnet hosts block Tor exits, then direct is the only way.
- Tor downloads can take hours: they run on the VPS, the lab can be off.
- The pull runs over fibre instead of the VPN (VPN providers throttle large downloads).
- The VPS is deleted after the case (hourly billing), with all leak data on it.

## Files

| File | Where | What |
|---|---|---|
| `cloud-init.yaml` | Hetzner "Cloud config" at server creation | Installs Tor, torsocks, curl, wget, rsync, tmux, updates; key-only SSH; user `drop` limited to read-only rsync of `/data/out`; mounts an attached volume at `/data`; installs `leak-fetch` |
| `leak-fetch` | VPS `/usr/local/bin` (via cloud-init) | Download single URLs, a URL list (3 in parallel, separate Tor circuits) or a recursive directory mirror. `.onion` via Tor, clearnet direct or `--tor`. Resume, retries, SHA256SUMS |
| `leak-pull` | Leak VM `/usr/local/bin` | Pull a case from the VPS into `/cases/datashare/docs/<case>/`, resume, retries, hash check |

## One-time setup

### 1. Key in the leak VM (700)

```bash
ssh-keygen -t ed25519 -f ~/.ssh/leak_vps -N "" -C leak-vm
cat ~/.ssh/leak_vps.pub
```

This key can only read `/data/out` on the VPS (forced `rrsync -ro`), nothing else. Its public key goes **only into the cloud config** (`PASTE_LEAK_VM_PUBLIC_KEY`), never under Hetzner SSH keys; `leak-pull` uses the private key automatically. The laptop key (Hetzner SSH keys) is separate and gives root access.

### 2. Hetzner project `leak-dl` (separate from other projects)

- **Security → SSH keys:** add the laptop's public key (admin access as root).
- **Firewalls → Create:** `leak-dl-fw`, inbound TCP 22 from the home public IPv4 only (`/32`, check on a home device without VPN, e.g. `curl https://ifconfig.me`). Outbound open. If the home IP changes, edit this rule.
- **Primary IPs → Create:** one IPv4, kept between cases (small monthly cost) so the OPNsense alias stays valid. IPv6 is free and comes with each server.

### 3. OPNsense

1. VM 700 gets a fixed IP outside the DHCP range: Ubuntu Settings → Network → Wired → IPv4 **Manual**, e.g. `10.10.10.70` (outside the DHCP range), `255.255.255.0`, gateway `10.10.10.1`, DNS `10.10.10.1`.
2. Firewall → Aliases: `LEAK_VM` (host) `10.10.10.70`, `LEAK_VPS` (host) the Primary IP.
3. Firewall → Rules → LAN, new rule **above** "Default allow LAN to any": Pass, IPv4, TCP, source `LEAK_VM`, destination `LEAK_VPS`, port 22 (SSH), Advanced → Gateway **WAN_DHCP** (the WAN gateway), description "Leak VM pulls from download VPS via WAN". Apply.

Source NAT is Hybrid, so the automatic WAN NAT rule covers it. Everything else from 700 still goes through the VPN and the kill switch.

### 4. leak-pull in the leak VM

```bash
sudo install -m 755 leak-pull /usr/local/bin/leak-pull   # from this folder
leak-pull --set-ip <Primary IP>
```

### 5. Cloud config with the 700 key (once)

1. Open `cloud-init.yaml` on the laptop in an editor.
2. In the line `command="/usr/bin/rrsync -ro /data/out",restrict PASTE_LEAK_VM_PUBLIC_KEY` replace only `PASTE_LEAK_VM_PUBLIC_KEY` with the output of `cat ~/.ssh/leak_vps.pub` from 700 (`ssh-ed25519 AAAA... leak-vm`). One line, keep the leading spaces.
3. Save as `cloud-init-leak.yaml` (or in the password manager). At server creation: section **Cloud config**, paste everything (first line `#cloud-config`).

Copy the key from 700 to the laptop via the noVNC clipboard panel (it is a public key, not secret).

## Per case

1. **Create server** in project `leak-dl`:
   - Location: an EU location (included traffic), image **Ubuntu 24.04**, smallest shared x86 type (2 vCPU / 4 GB is enough, Tor is the bottleneck)
   - Networking: the kept **Primary IPv4** + IPv6
   - SSH key: laptop key. Firewall: `leak-dl-fw`
   - Volume (if the leak is larger than ~30 GB): size = leak size + 20 %, **ext4, manual mount** (cloud-init mounts it at `/data`)
   - Cloud config: paste `cloud-init-leak.yaml` from step 5
2. Laptop: `ssh root@<IP>` (new host key each server: `ssh-keygen -R <IP>` first), then `cloud-init status --wait`.
3. Download in tmux (keeps running after logout):
   ```bash
   tmux new -s dl
   leak-fetch <case> 'http://<onion>/path/file.7z'          # one or more URLs
   leak-fetch <case> -l urls.txt                            # list, 3 in parallel
   leak-fetch <case> -r 'http://<onion>/files/'             # whole directory listing
   leak-fetch <case> 'https://files.example/leak.zip'       # clearnet: direct
   leak-fetch --tor <case> 'https://files.example/leak.zip' # clearnet via Tor
   ```
   Detach with Ctrl+B, D. Back later: `tmux attach -t dl`. Check Tor first if needed: `torsocks curl -s https://check.torproject.org/api/ip`.
4. Leak VM: `cases-open`, then `leak-pull <case>` (resumes after interruptions, checks SHA256SUMS). After a new server: `leak-pull --set-ip <IP>` again (forgets the old host key).
5. leak-hunter: index the case.
6. Clean up: `rm -rf /data/out/<case>` on the VPS, then either delete or keep the server (see below).

### Delete or keep the server

Hetzner bills a server until it is **deleted**, powered off or not (same for volumes and Primary IPs).

| | Delete after each case | Keep it, power off when idle |
|---|---|---|
| Cost | hours of use only | full monthly price of server + volume (powering off saves nothing) |
| Effort | create from cloud-init (~3 min), `leak-pull --set-ip` and `ssh-keygen -R` for the new host key | power on, done; host key stays |
| Leak data | gone with the server | stays until you delete it: `rm -rf /data/out/<case>` after every pull |
| Updates | always fresh | unattended-upgrades runs while on; `apt upgrade` after long breaks |

Keeping it is fine for frequent cases with the smallest type. Detach and delete large volumes when not needed, they are billed per GB.

## Security notes

- Leak files are never opened on the VPS, only downloaded and hashed. No web server, password SSH off, firewall to the home IP.
- `drop` key: `command="/usr/bin/rrsync -ro /data/out",restrict`, no shell, no forwarding, no writes, no paths outside `/data/out` (tested with rrsync 3.2.7).
- The VPS sees the home IP (SSH from the lab and the laptop), the leak site only sees Tor.
- Check the provider's terms (Tor client use is fine at Hetzner, running exits or relays is not part of this) and that your employer allows it.

## Tested

leak-fetch download logic (resume after interruption, already complete = HTTP 416, 404 without leftover file, URL list) and the rrsync restriction (read ok, `../` escape blocked, write blocked) tested locally 2026-11-09. Tor and the Hetzner parts are tested on the first real server.
