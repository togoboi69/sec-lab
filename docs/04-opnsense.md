# 04 OPNsense VM

OPNsense 26.7 as gateway between `vmbr1` (analysis) and the internet via Proton.

## VM 100 (opnsense)

| Setting | Value |
|---|---|
| VM ID / name | `100` / `opnsense` |
| Start at boot | yes |
| OS type | Other |
| CPU | 2 cores, type `host` |
| RAM | 4096 MB |
| Disk | 20 GB on `nvme` |
| net0 | VirtIO, bridge `vmbr0`, no firewall flag → OPNsense **WAN** (`vtnet0`) |
| net1 | VirtIO, bridge `vmbr1`, no firewall flag → OPNsense **LAN** (`vtnet1`) |
| CD/DVD | removed after install ("Do not use any media") |

Download the ISO directly to Proxmox: `local`, ISO Images, Download from URL, paste the `dvd-amd64.iso.bz2` link from opnsense.org, decompression **bz2**.

## Important: avoid IP conflict with the home router

OPNsense's default LAN IP is `<HOME_GW>`, the same as the home router. If its LAN lands on `vmbr0`, it takes over the home network (DHCP, gateway) and other PCs lose internet. This happened once during setup.

Safe procedure:

1. Before first start: Hardware, net0, Edit, tick **Disconnect** (`link_down=1`).
2. Configure interfaces and LAN IP in the console.
3. Only then untick Disconnect.

Recovery if it happens: stop VM 100, on affected PCs `arp -d *`, `ipconfig /release`, `ipconfig /renew`.

## Install

1. Boot from ISO, log in as `installer` / `opnsense`.
2. Install (UFS), select the 20 GB disk, set root password, reboot, remove ISO.

## Console configuration

Option **1** (Assign interfaces):

```
LAGGs?  n
VLANs?  n          (answering y by mistake: Ctrl+C and restart)
WAN:    vtnet0
LAN:    vtnet1
Optional: <Enter>
Proceed: y
```

Option **2**, LAN:

```
DHCP: n
IPv4: 10.10.10.1 / 24
Upstream gateway: <Enter>
IPv6 via WAN tracking: n, via DHCP6: n, address: <Enter>
DHCP server on LAN: y, range 10.10.10.100 - 10.10.10.200
Web GUI to HTTP: n
New self-signed cert: y
Restore web GUI defaults: n
```

Option **2**, WAN: DHCP `y`, IPv6 `n`.

Result:

```
LAN (vtnet1) -> v4: 10.10.10.1/24
WAN (vtnet0) -> v4/DHCP4: <OPN_WAN_IP>/24
```

Recommended: DHCP reservation for OPNsense WAN MAC on `<OPN_WAN_IP>` in the home router.

## Web GUI access from home LAN

The GUI is blocked on WAN by default. First access: console option 8, `pfctl -d`, then open `https://<OPN_WAN_IP>`.

Setup wizard:

- Timezone <your timezone>, DNS servers empty, Override DNS off, Unbound resolver on
- WAN: DHCP, **untick "Block private networks"** (home LAN is RFC1918)
- LAN: `10.10.10.1/24`

Permanent WAN rule (Firewall, Rules, WAN):

| Action | Proto | Source | Destination | Port | Description |
|---|---|---|---|---|---|
| Pass | TCP | WAN network | This Firewall | https | GUI from home LAN |

Also: Interfaces, [WAN], **Block private networks** unticked.

Emergency access at any time: Proxmox console of VM 100, option 8, `pfctl -d`. Any Apply in the GUI re-enables pf.
