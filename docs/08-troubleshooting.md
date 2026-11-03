# 08 Troubleshooting and lessons learned

Issues hit during the initial setup and their fixes.

| Symptom | Cause | Fix |
|---|---|---|
| POST: "GPT header corruption has been detected, please check SATA mode" | dd-written hybrid Proxmox ISO on the USB stick | Harmless. Press F1, boot via the boot menu or Boot Override. Do not run GPT recovery on the stick. |
| USB stick not listed in Boot Override | Stick plugged in after power-on / not bootable | Plug in before power-on, rear port, reflash in DD mode. Fast Boot off, Secure Boot "Other OS" if needed. |
| Installer: "No support for hardware-accelerated KVM virtualization" | VMX disabled in BIOS | Advanced, CPU Configuration, Intel VMX on. Can be done after install. |
| `apt update`: 401 Unauthorized from enterprise.proxmox.com | Enterprise repo still enabled (deb822 `.sources`) | See [02](02-proxmox-install.md), disable in every file containing the URL. |
| Home PC suddenly without internet, gateway shows OPNsense login | OPNsense LAN default `<HOME_GW>` collided with home router | Stop VM 100, `arp -d *`, `ipconfig /release` and `/renew`. Configure OPNsense with net0 disconnected. |
| net0 Disconnect "not saved" | Edit dialog closed without OK | Check Hardware list for `link_down=1` before starting the VM. |
| OPNsense GUI not reachable from laptop | WAN blocks private networks, no WAN rule, pf re-enabled by Apply | Console option 8 `pfctl -d`, add WAN rule, untick "Block private networks". |
| Interface assignment asks for VLAN tag | Answered `y` to VLANs | Ctrl+C, run option 1 again, answer `n`. |
| Menu name "Outbound NAT" missing | Renamed in OPNsense 26.x | Firewall, NAT, **Source NAT**. |
| No "Enable WireGuard" switch | Removed in newer versions | Instance and peer `Enabled` plus Apply. |
| Anti-lockout setting not under Administration | Moved | Firewall, Settings, Advanced, "Disable administration anti-lockout rule". |
| REMnux Console button downloads `.vv` files | Display set to QXL/SPICE | Display Default (std), or Console dropdown → noVNC |
| REMnux clipboard not working | GNOME on Wayland | `WaylandEnable=false` in `/etc/gdm3/custom.conf`, reboot, check `x11` |
| CyberChef download script silent, empty folder | Asset named `CyberChef_<hash>.zip`, REMnux curl fake UA | Pattern `CyberChef_[^"]*\.zip`, `-A "curl"` |
| Firefox autostart opens two windows | Two URLs after `--new-window` | Second URL with `--new-tab` |
| Windows: no disk in setup | No VirtIO SCSI driver | Load driver `vioscsi\w10\amd64` from virtio-win CD |
| Windows clipboard works only once | Old Spice agent from virtio bundle | Latest spice-guest-tools, only one agent service enabled, copy in VM first |
| Windows resolution greyed out (1280x800) | UEFI basic display adapter | OVMF Platform Configuration → Preferred Resolution |
| Dialog buttons hidden behind taskbar | Low resolution | Enter, auto-hide taskbar, Alt+Space → M |
| Box unreachable after power cut, black screen | BIOS reset, boot halted at "recover BIOS setting" / "CPU Fan Error" waiting for F1 | Monitor on the active GPU output, F1, restore BIOS settings ([01](01-hardware.md)), disable "Wait for F1 if error" |
| FLARE: Node-based packages fail (ExperimentalWarning) | Script treats stderr warning as error | `$env:NODE_NO_WARNINGS = "1"` then retry |
| Large downloads (hundreds of MB) through the tunnel sometimes break off (`curl: (56)`), same file works on the laptop | Not fully confirmed. MTU 1420 / MSS 1380 applied, did not fully fix it. Suspect: gateway monitor marks PROTON_GW down while the tunnel is saturated, "Skip rules when gateway is down" then cuts states. Also possible: Proton server. Intermittent, a retry often succeeds | Accepted as known issue (samples are small, fails closed, no leak). Workaround: `curl.exe -C - --retry` resume loop. If it gets annoying: check System → Log Files → Gateways for PROTON_GW alarms and raise PROTON_GW thresholds (latency 1000 ms, loss 40 %, longer time period), or switch Proton server |
| FLARE: checksum mismatch | Upstream file changed | Skip, or `--ignore-checksums` knowingly |
| INetSim floods terminal with `Argument ... isn't numeric ... IO/Select.pm line 68` | Old INetSim Perl code vs. newer Perl on Ubuntu 24.04, harmless | Filter only stderr: `sudo inetsim 2> >(grep --line-buffered -v "IO/Select.pm line 68" >&2)`. Do not pipe all output, Perl then buffers stdout and INetSim appears stuck at "Forking services..." |
| Detonation PCAP full of Microsoft domains | Windows background traffic answered by INetSim | Wireshark `IOCs` filter or `pcap-iocs.sh` ([12](12-offline-detonation.md)) |
| Host hard-resets when starting VMs, reset loops at boot, no log entry | Hardware (see [01](01-hardware.md)). In the reference build fixed by removing the dedicated GPU and reseating the NVMe (heatsink pad foil removed) | Log check: `journalctl --list-boots`, `journalctl -b -1 -n 40`; tests: stress-ng CPU/RAM, boot with `modprobe.blacklist=nvme`; next suspect PSU |
| BIOS shows "recover BIOS setting" after unplugging | Empty CMOS battery | Replace CR2032, reload your BIOS profile |
| VM console says "Guest not running" although VM runs | Console opened before the VM was started | Reload the console (F5) |
| VM without internet after re-enabling tunnel | Gateway still marked down, stale states | Wait for PROTON_GW online, Apply LAN rules, reset state table. |

## Useful commands

Proxmox host:

```bash
qm list                      # VMs and state
qm config 100                # OPNsense VM config
ip -br a                     # bridges and IPs
grep -c vmx /proc/cpuinfo    # VT-x check
smartctl -a /dev/nvme0n1     # disk health
```

OPNsense shell (console option 8):

```bash
pfctl -d / pfctl -e          # firewall off / on (emergency only)
wg show                      # tunnel status
ping -S 10.2.0.2 1.1.1.1     # ping through the tunnel
configctl service reload all # same as menu option 11
```
