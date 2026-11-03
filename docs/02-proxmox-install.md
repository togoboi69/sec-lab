# 02 Proxmox installation

Proxmox VE 9 (Debian 13 Trixie).

## Boot stick

1. Download the Proxmox VE ISO from proxmox.com.
2. Flash with Rufus. Rufus reports "ISOHybrid image detected" and forces **DD mode**. That is correct.
3. Alternatives: balenaEtcher, or `dd if=proxmox.iso of=/dev/sdX bs=4M status=progress conv=fsync`.

## Booting the stick

- Plug the stick into a **rear USB port before power-on**. Many boards only build the boot list at startup.
- Open the boot menu (often F8, F11 or F12), pick the **UEFI: USB ...** entry.
- If the stick does not appear: Fast Boot off, Secure Boot OS Type "Other OS", reflash or try another stick.

## Installer choices

| Field | Value |
|---|---|
| Mode | Graphical |
| Target disk | `/dev/sda` (SATA SSD), **not** the NVMe |
| Filesystem | ext4 |
| Country / timezone / keyboard | your own |
| Root password | set in installer (also the web UI login) |
| Email | notifications only, not a login |
| Management interface | onboard NIC |
| Hostname (FQDN) | `proxmox` (shown as node name in the UI) |
| IP | `<PVE_IP>/24` (static, outside router DHCP range) |
| Gateway / DNS | `<HOME_GW>` |

The installer warned "No support for hardware-accelerated KVM virtualization". Cause: VMX was off in BIOS. Install can continue, enable VMX afterwards. Verify after boot:

```bash
grep -c vmx /proc/cpuinfo   # > 0 means VT-x is on
```

The installer works offline. Plug in the LAN cable afterwards; no reconfiguration needed.

## First login

- `https://<PVE_IP>:8006`, user `root`, realm **Linux PAM standard authentication**.
- "No valid subscription" popup: normal, click OK.

## Repositories (no subscription)

Proxmox 9 uses deb822 `.sources` files.

1. Node, Updates, Repositories: disable **pve-enterprise** (and ceph enterprise if present).
2. Add the **No-Subscription** repo.
3. If `apt update` still returns `401 Unauthorized` from `enterprise.proxmox.com`, disable it in every file:

```bash
grep -rn enterprise.proxmox.com /etc/apt/sources.list /etc/apt/sources.list.d/

for f in $(grep -rl enterprise.proxmox.com /etc/apt/sources.list.d/); do
  case "$f" in
    *.sources) sed -i '/^Enabled:/d' "$f"; sed -i '/^Types:/a Enabled: no' "$f" ;;
    *.list)    sed -i 's/^deb/#deb/' "$f" ;;
  esac
done

apt update && apt full-upgrade -y
```

Reboot after the first upgrade (new kernel).
