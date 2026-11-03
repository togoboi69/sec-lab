# 13 Sample Transfer UI

Web UI on the Proxmox host that replaces the shell scripts `sample2iso.sh` / `sample-clean.sh` from [12](12-offline-detonation.md). Code in [tools/transfer-ui](../tools/transfer-ui/).

URL: **https://<PVE_IP>:8443** (same certificate as the Proxmox UI, warning expected)

## Features

- **VMs:** status of 301, 302, 402 with **Start** buttons, **Roll back to clean** for 402 (stops the VM, rolls back, deletes its transfer ISO; asks for confirmation)
- **Files in VM 301:** name, size, SHA256 of everything in `/home/remnux/Downloads` (read via guest agent)
- **Send to:** choose target VM (default 402 or 302). Builds `sample-transfer-<vmid>.iso`, checks the hash, attaches it as CD drive `ide2`
- **Transfer ISOs:** remove from the VM and delete
- **Log** of the last actions (also in `journalctl -u sample-transfer`)

## Security

- Runs as root on the hypervisor, so it is locked down:
  - listens only on `<PVE_IP>:8443`, only clients from `<HOME_LAN>` (analysis VMs cannot reach the host anyway: vmbr1/vmbr2 have no host IP)
  - HTTP Basic auth over TLS, password stored as PBKDF2-SHA256 in `/etc/sample-transfer/auth` (root only), 1.5 s delay per failed login
  - CSRF token on every action, strict Content-Security-Policy, no framing
  - only configured VMs and actions; filenames must match the current listing in 301 (no path traversal); all commands run without a shell
- File size limit 10 MB (guest agent buffer).
- Target VMs without a CD drive (e.g. REMnux 302) must be shut down once for the first transfer so `ide2` can be added.

## Install

From the laptop (Windows has `scp` built in), with the `transfer-ui` folder from the repo:

```powershell
scp -r transfer-ui root@<PVE_IP>:/root/
```

Proxmox shell:

```bash
bash /root/transfer-ui/install.sh          # first run: creates /etc/sample-transfer/config.json and stops
nano /etc/sample-transfer/config.json      # set "bind" to <PVE_IP> and "allowed_networks" to <HOME_LAN>
bash /root/transfer-ui/install.sh          # second run: asks for the web login, enables the service
```

The installer installs `genisoimage`/`jq`, copies the app to `/opt/sample-transfer/`, creates the config from `config.example.json`, asks for the web login (first install only), and enables `sample-transfer.service`.

Update: copy the folder again and rerun `install.sh` (keeps login and config).

## Configuration

`/etc/sample-transfer/config.json` (see `tools/transfer-ui/config.example.json`). Besides `bind` and `allowed_networks`, adjust the VM IDs if yours differ:

```json
{
  "bind": "<PVE_IP>",
  "allowed_networks": ["<HOME_LAN>"],
  "targets": [402, 302],
  "status_vms": [301, 302, 402],
  "rollback_vms": {"402": "clean"},
  "max_bytes": 10485760
}
```

Then `systemctl restart sample-transfer`. Other keys: `bind`, `port`, `allowed_networks`, `source_vm`, `source_dir`, `iso_dir`, `iso_storage`, `cert`, `key`.

Change the password: `python3 /opt/sample-transfer/app.py --set-password && systemctl restart sample-transfer`.

## Operations

```bash
systemctl status sample-transfer
journalctl -u sample-transfer -f
systemctl disable --now sample-transfer   # switch off
```

Tested against mocked `qm`/`pvesh` (send, clean, start, rollback, auth, CSRF, invalid target, path traversal) and on the real host: install, start VMs, send test file 301 → 402 work.
