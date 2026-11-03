# Sample Transfer UI

Small web UI on the Proxmox host for moving samples from `remnux-work` (301) into the detonation VMs as a read-only ISO. See [docs/13](../../docs/13-transfer-ui.md).

Files:

- `app.py`: the app (Python standard library only)
- `sample-transfer.service`: systemd unit
- `install.sh`: installer (run as root on the Proxmox host)
- `config.example.json`: copied to `/etc/sample-transfer/config.json` on first install; set `bind` and `allowed_networks`

Install: copy this folder to the Proxmox host, run `bash install.sh`, edit `/etc/sample-transfer/config.json`, run `bash install.sh` again.
