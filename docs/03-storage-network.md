# 03 Storage and networking

## Storage

| Storage | Disk | Type | Use |
|---|---|---|---|
| `local` | SATA SSD | Directory | ISO images, backups |
| `local-lvm` | SATA SSD | LVM-Thin | spare |
| `nvme` | NVMe SSD | LVM-Thin | **all VM disks** |

Setup of `nvme`:

1. Node, Disks: select `/dev/nvme0n1` (whole disk, not the partition), **Wipe Disk**.
2. Node, Disks, LVM-Thin, **Create: Thinpool**: disk `/dev/nvme0n1`, name `nvme`, Add Storage ticked.

LVM-Thin gives snapshots and fast linked clones from templates.

## Network

| Interface | Type | Ports | IP | Purpose |
|---|---|---|---|---|
| `nic0` | physical | | | onboard NIC |
| `vmbr0` | Linux bridge | `nic0` | `<PVE_IP>/24`, gw `<HOME_GW>` | home LAN, Proxmox UI, OPNsense WAN |
| `vmbr1` | Linux bridge | **none** | none | isolated analysis network, only reachable via OPNsense LAN |

Create `vmbr1`: Node, System, Network, Create, Linux Bridge. Name `vmbr1`, leave IPv4, gateway and bridge ports **empty**, autostart on, comment `analysis-isolated`. Then **Apply Configuration**.

Resulting `/etc/network/interfaces` (relevant part):

```
auto vmbr0
iface vmbr0 inet static
    address <PVE_IP>/24
    gateway <HOME_GW>
    bridge-ports nic0
    bridge-stp off
    bridge-fd 0

auto vmbr1
iface vmbr1 inet manual
    bridge-ports none
    bridge-stp off
    bridge-fd 0
#analysis-isolated
```

## Rule for every analysis VM

- Network device on **`vmbr1`** only
- Model VirtIO, **Proxmox firewall flag unticked** (filtering is done by OPNsense)
- Disk on storage `nvme`
- Never attach an analysis VM to `vmbr0`
