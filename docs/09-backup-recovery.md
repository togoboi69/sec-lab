# 09 Backup and recovery

## OPNsense config

System, Configuration, Backups, **Download configuration**. Store the XML outside this repo (password manager attachment or encrypted storage). It contains the WireGuard private key and password hashes.

Restore: fresh OPNsense install, then System, Configuration, Backups, Restore, or console option 13.

Take a new export after every rule or VPN change.

## Proxmox snapshots

| VM | Snapshot | State |
|---|---|---|
| 100 opnsense | `working-vpn` | Tunnel, NAT, rules, kill switch verified |

VM, Snapshots, Take Snapshot. Roll back from the same page.

## Proxmox backups

Datacenter, Backup, Add: schedule `vzdump` of VM 100 and templates to `local` (or later a NAS / external disk). Since the box is only powered on occasionally, run backups manually: VM, Backup, Backup now.

## Full rebuild order

1. BIOS settings ([01](01-hardware.md))
2. Proxmox install and repos ([02](02-proxmox-install.md))
3. `nvme` thin pool and `vmbr1` ([03](03-storage-network.md))
4. OPNsense VM with net0 disconnected, restore config XML ([04](04-opnsense.md))
5. Reconnect net0, check tunnel and gateway
6. Run [07](07-testing.md)
