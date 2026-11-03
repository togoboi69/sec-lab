# Ideas and extensions

Optional things that build on the base lab.

## Hardening and convenience

- **Wake-on-LAN** for the Proxmox host (BIOS: ErP off, power on by PCIe; `ethtool -s nic0 wol g` as `post-up` in `/etc/network/interfaces`).
- **SSH key login** for Proxmox, password SSH off. **2FA (TOTP)** for the Proxmox web UI.
- **Isolate VMs inside vmbr1 from each other.** VMs on the same bridge talk directly, without passing OPNsense. If an analysis VM gets infected, it could reach the others. Proxmox firewall rules or port isolation can prevent that.
- **Real memory usage of Windows VMs** in Proxmox: enable the ballooning device with minimum = maximum memory, so the VirtIO balloon service only reports usage.

## Detonation

- **Suricata on the INetSim VM**: run ET Open (or your own) rules offline against each PCAP (`suricata -r capture.pcap`). Set `HOME_NET` to the victim only (e.g. `10.20.20.10`), otherwise traffic to the INetSim address counts as internal and many rules do not fire. Rules can be brought into the offline VM with the transfer UI.
- **Quieter Windows** in the FLARE build VM: disable root certificate auto-update, NCSI active probing, telemetry, SmartScreen, Edge/OneDrive updates, then rebuild the template. Cleaner PCAPs, but do not strip so much that samples behave differently.
- **Text IOC list from PCAPs** with tshark (DNS names, HTTP requests, TLS SNI minus Microsoft noise); a script is in [docs/12](docs/12-offline-detonation.md).

## Kasm

- **Per-session VPN exit country** with Kasm egress gateways (one WireGuard provider per country, `MTU = 1340` because it runs inside the existing tunnel). Only useful for geo-blocked phishing kits; the simpler alternative is switching the OPNsense VPN server temporarily.
- **Session limits** on the All Users group (`idle_disconnect`, `keepalive_expiration`, `session_time_limit`).

## Practice network

- **vmbr3** without internet for intentionally vulnerable targets (Metasploitable, VulnHub), Kali with a second NIC there. Do not put vulnerable VMs on vmbr1: they would get internet and sit next to your analysis VMs.

## Infrastructure as code

- Export VM configs (`qm config`) into the repo, or define VMs with Terraform (Proxmox provider) / Ansible.

## Known issues

- Very large downloads (hundreds of MB) through the WireGuard tunnel occasionally break off. Samples are small, and the failure is fail-closed. Workaround: `curl -C - --retry` resume loop; possible cause: gateway monitoring marking the VPN gateway down while the tunnel is saturated (raise its thresholds).
