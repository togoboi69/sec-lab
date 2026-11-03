# 07 Verification tests

Run after any change to OPNsense rules, NAT or VPN, and after switching Proton servers.

## Test VM

| Setting | Value |
|---|---|
| VM ID / name | `200` / `test-ubuntu` |
| ISO | Ubuntu Desktop 26.04.1 (live, "Try Ubuntu") |
| CPU / RAM / disk | 2 cores host / 4096 MB / 32 GB on `nvme` |
| Network | VirtIO on `vmbr1`, no firewall flag |

## Checklist

| # | Test (inside VM on vmbr1) | Expected | Result |
|---|---|---|---|
| 1 | Browser: `ifconfig.me` | Proton IP, not home IP | Pass |
| 2 | Browser: `dnsleaktest.com` standard test | Only Proton resolvers | Pass |
| 3 | `ping -c 3 <HOME_GW>` | Fails | Pass |
| 4 | Browser: `https://<OPN_WAN_IP>` | Does not load | Pass |
| 5 | Browser: `https://10.10.10.1` | Does not load | Pass |
| 6 | Kill switch: disable Proton peer in OPNsense, then `ifconfig.me` | No internet (not home IP) | Pass |
| 7 | Re-enable peer, wait for gateway online | Internet via Proton again | Pass |

## Quick CLI version

```bash
curl -s ifconfig.me; echo
resolvectl status | grep -i 'dns server'
ping -c 2 -W 2 <HOME_GW> && echo "FAIL: home LAN reachable" || echo "OK: home LAN blocked"
curl -sk -m 5 https://10.10.10.1 >/dev/null && echo "FAIL: GUI reachable" || echo "OK: GUI blocked"
curl -sk -m 5 https://<OPN_WAN_IP> >/dev/null && echo "FAIL: GUI reachable" || echo "OK: GUI blocked"
```
