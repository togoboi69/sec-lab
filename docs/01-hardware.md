# 01 Hardware

Any reasonably recent desktop works. The reference build is a repurposed gaming PC.

## Requirements

| Part | Minimum | Comfortable | Notes |
|---|---|---|---|
| CPU | 4 cores with Intel VT-x / AMD-V | 8 cores | VT-d / AMD-Vi (IOMMU) nice to have |
| RAM | 16 GB | 32 GB | The firewall uses 4 GB, a Windows analysis VM 8 GB, Linux VMs 4 GB each |
| Disk 1 | 128 GB SSD | 250 GB+ SSD | Proxmox system disk (SATA is fine) |
| Disk 2 | 500 GB SSD | 1 TB NVMe | VM storage (thin pool for templates, clones, snapshots) |
| NIC | 1x Ethernet | | Wi-Fi is not practical for Proxmox |
| GPU | not needed | | Integrated graphics is enough for BIOS/console; Proxmox runs headless |

Reference build: 8-core Intel desktop CPU, 32 GB DDR4, SATA SSD for Proxmox, 1 TB NVMe for VMs, onboard Intel NIC, dedicated GPU removed (see below).

## BIOS/UEFI settings

Names differ per vendor; use the BIOS search if available.

| Setting | Value |
|---|---|
| SATA mode | **AHCI** (not RAID / Intel RST) |
| Intel VMD (newer Intel boards) | Disabled |
| Intel VMX / VT-x (AMD: SVM) | **Enabled** |
| VT-d / IOMMU | Enabled |
| Boot option #1 | Proxmox disk |
| Halt on POST errors ("Wait for F1 if error") | Disabled, so the box boots unattended |
| CPU fan warning | Fix the fan header, or set the check to ignore only if the cooler demonstrably works |
| Restore on AC power loss | optional: Power On / Last State |

Save the settings as a BIOS user profile if your board supports it, so you can restore them after a reset.

## Lessons learned on old hardware

- **BIOS forgets its settings** after unplugging or a power cut: empty CMOS battery (CR2032). Replace it and reload your profile. After a reset, VT-x/VT-d are usually off again and VMs will not start.
- **"GPT header corruption" at POST** with the Proxmox USB stick plugged in: harmless (hybrid ISO layout). Do not let the BIOS "recover" the stick.
- **Hard resets without any log entry** (host reboots when starting VMs, reset loops early in boot): this is hardware, not software. Proceed by elimination:
  - temperatures: `apt install lm-sensors && sensors`
  - CPU load: `stress-ng --cpu <cores> --timeout 120s`
  - RAM: `stress-ng --vm 4 --vm-bytes 85% --verify --timeout 600s`
  - boot once without NVMe driver (GRUB, append `modprobe.blacklist=nvme`) to rule out NVMe I/O
  - try another wall socket without power strip
  - **remove the dedicated GPU** and reseat drives and power connectors
  - last suspect: the power supply (swap test)

  In the reference build the resets stopped after removing the GPU and reseating the NVMe. While doing that, the protective **foil on the M.2 heatsink thermal pad** turned out to have never been removed. Check yours.
- NVMe load test (temporary thin volume, no VM touched):

  ```bash
  apt install -y fio
  lvcreate -V 20G -T nvme/nvme -n iotest
  fio --name=nvmetest --filename=/dev/nvme/iotest --rw=randrw --bs=64k --iodepth=32 --ioengine=libaio --direct=1 --runtime=120 --time_based --group_reporting
  lvremove -y nvme/iotest
  ```

## Capacity planning (32 GB RAM)

| VM | RAM |
|---|---|
| Proxmox host | ~2 GB |
| OPNsense | 4 GB |
| REMnux | 4 GB each |
| FLARE-VM | 8 GB each |
| Kasm | 10 GB |
| Kali | 8 GB |

Shut down what you do not use. Thin provisioning lets the sum of virtual disk sizes exceed the pool (LVM warns about it); watch real usage with `lvs` (keep `Data%` below ~80 %).
