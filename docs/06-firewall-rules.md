# 06 Firewall, NAT, kill switch, DNS

## Source NAT (formerly "Outbound NAT")

Firewall, NAT, Source NAT. Mode: **Hybrid**.

| Interface | Version | Proto | Source | Destination | Translate source IP | Description |
|---|---|---|---|---|---|---|
| PROTON | IPv4 | any | LAN network | any | **PROTON address** | LAN via Proton |

Without this, packets leave the tunnel with 10.10.10.x source addresses and Proton drops them. The automatic WAN NAT rules remain but are never used by LAN traffic (kill switch below).

## LAN rules (order matters, top to bottom)

Firewall, Rules, LAN:

| # | Action | Ver | Proto | Source | Destination | Dst port | Gateway | Description |
|---|---|---|---|---|---|---|---|---|
| 1 | Pass | IPv4 | TCP/UDP | LAN network | This Firewall | DNS (53) | default | DNS to OPNsense |
| 2 | Block | IPv4 | any | any | This Firewall | any | | Block VMs to firewall |
| 3 | Block | IPv4 | any | any | WAN network | any | | Block VMs to home LAN |
| 4 | Pass | IPv4 | TCP | LEAK_VM | LEAK_VPS | SSH (22) | **WAN gateway** | Optional: leak VM pulls from download VPS via WAN ([16](16-leak-analysis.md)) |
| 5 | Pass | IPv4 | any | LAN network | any | any | **PROTON_GW** | Default allow LAN to any |
| 6 | (disabled) | IPv6 | any | LAN network | any | any | | Default allow LAN IPv6 |

Notes:

- DNS port goes in **Destination** port, not source port (mistake made once during setup).
- New rules land at the bottom. Select them and use the move icon to place them above the default allow rule.
- IPv6 allow rule disabled: the Proton config is IPv4 only, this prevents IPv6 leaks.

## WAN rules

| Action | Proto | Source | Destination | Port | Description |
|---|---|---|---|---|---|
| Pass | TCP | WAN network | This Firewall | https | GUI from home LAN |

Aliases for rule 4 (only if you use the download VPS): `LEAK_VM` = static IP of the leak VM, `LEAK_VPS` = the VPS's fixed IPv4. With Source NAT in Hybrid mode, the automatic WAN NAT rule covers it; everything else stays in the tunnel.

## Kill switch

Firewall, Settings, Advanced: **Skip rules when gateway is down** = on.

When `PROTON_GW` goes down, the default allow rule is skipped entirely, so LAN traffic matches nothing and is dropped. It never falls back to the WAN default route.

Recovery after a tunnel outage: gateway needs up to a minute to be marked online again. If traffic still fails: Apply on LAN rules, or console option 11, or Firewall, Diagnostics, States, reset state table.

## Lock VMs out of the GUI

- Firewall, Settings, Advanced: **Disable administration anti-lockout rule** = on
- Rule 2 blocks everything to the firewall except DNS
- Optional extra: System, Settings, Administration, Listen Interfaces = WAN only

## DNS via tunnel

Services, Unbound DNS, Query Forwarding:

| Enabled | Domain | Server IP | Port | Description |
|---|---|---|---|---|
| yes | `internal` | 127.0.0.1 | 53053 | auto-created, leave as is |
| yes | (empty = all) | `10.2.0.1` | 53 | Proton DNS |

**Use System Nameservers**: off.

Side effect: OPNsense itself resolves via Proton too, so if the tunnel is down OPNsense has no DNS (affects its own updates).

## MTU / MSS on the tunnel

Large downloads through the tunnel broke off mid-transfer several times. WireGuard adds 60 to 80 bytes per packet, so full 1500-byte packets do not fit. Standard fix:

Interfaces → [PROTON]: **MTU `1420`**, **MSS `1380`** (MTU minus 40 bytes IP/TCP headers), Save, Apply.

MSS clamping makes every TCP connection through the tunnel agree on packets small enough to fit. Low risk, revert by clearing both fields. Test with one large download without resume.

Note: large downloads still break off occasionally. Treated as known issue, see [08](08-troubleshooting.md).

## Proxmox firewall

Not used. The "Firewall" checkbox on VM network devices is unticked, all filtering happens in OPNsense.
