# 12 Offline detonation network (vmbr2)

Isolated network for executing samples without real internet. REMnux simulates the internet with INetSim, so samples behave as if online and every DNS query and connection attempt is logged.

## Why

Running malware on `vmbr1` gives it real internet via Proton: real C2 contact, next-stage downloads, exfiltration, the attacker noticing the analysis, abuse of the Proton IP. On `vmbr2` there is no route out at all.

## Layout

```
vmbr2  (no physical port, no OPNsense, no internet)
  ├── 302 remnux-inetsim   10.20.20.1/24   fake internet: DNS, HTTP(S), SMTP, FTP ..., gateway for 402
  └── 402 flare-detonate   10.20.20.10/24  gw 10.20.20.1, DNS 10.20.20.1
```

- `vmbr2`: Linux bridge, no ports, no IP, comment `detonation-offline`.
- Both VMs are linked clones of the templates (9000, 9011). net0 switched to `vmbr2` **before first boot**.
- No DHCP on vmbr2, static IPs.

Check bridges from the Proxmox shell:

```bash
qm config 302 | grep net0; qm config 402 | grep net0   # both bridge=vmbr2
```

## REMnux 302: static IP

REMnux uses netplan with **systemd-networkd** (from cloud-init, `50-cloud-init.yaml`, ens18 DHCP). NetworkManager shows ens18 as `unmanaged`, so `nmcli` does not work here.

```bash
echo 'network: {config: disabled}' | sudo tee /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg

sudo tee /etc/netplan/99-lab-offline.yaml >/dev/null <<'YAML'
network:
  version: 2
  ethernets:
    ens18:
      dhcp4: false
      dhcp6: false
      addresses: [10.20.20.1/24]
      nameservers:
        addresses: [10.20.20.1]
YAML
sudo chmod 600 /etc/netplan/99-lab-offline.yaml

sudo systemctl disable systemd-networkd-wait-online.service
sudo systemctl mask systemd-networkd-wait-online.service   # else boot waits ~2 min for DHCP

sudo netplan apply
ip -br a
```

- `99-` overrides `dhcp4: true` from `50-cloud-init.yaml` (netplan merges alphabetically).
- cloud-init network config disabled so it does not rewrite its file.
- No gateway: REMnux is the end of the line.

## FLARE 402: static IP

Admin PowerShell:

```powershell
$if = (Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1).Name
Set-NetIPInterface -InterfaceAlias $if -Dhcp Disabled
Get-NetIPAddress -InterfaceAlias $if -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false
New-NetIPAddress -InterfaceAlias $if -IPAddress 10.20.20.10 -PrefixLength 24 -DefaultGateway 10.20.20.1
Set-DnsClientServerAddress -InterfaceAlias $if -ServerAddresses 10.20.20.1
```

Do **not** run FakeNet-NG in FLARE at the same time (it intercepts locally).

## INetSim on REMnux

`/etc/inetsim/inetsim.conf`:

```bash
sudo sed -i 's/^#\?service_bind_address.*/service_bind_address 10.20.20.1/' /etc/inetsim/inetsim.conf
sudo sed -i 's/^#\?dns_default_ip.*/dns_default_ip 10.20.20.1/' /etc/inetsim/inetsim.conf
sudo sed -i 's/^# *start_service dns/start_service dns/' /etc/inetsim/inetsim.conf   # DNS was disabled by default
grep -nE "^(service_bind_address|dns_default_ip|start_service dns)" /etc/inetsim/inetsim.conf
```

Start script `~/bin/detonate-start.sh` (redirects every TCP/UDP connection, whatever the target IP, to INetSim, records a PCAP, starts INetSim):

```bash
#!/bin/bash
mkdir -p ~/captures
PCAP=~/captures/$(date +%Y%m%d-%H%M%S).pcap
sudo iptables -t nat -C PREROUTING -i ens18 -p tcp -j REDIRECT 2>/dev/null || sudo iptables -t nat -A PREROUTING -i ens18 -p tcp -j REDIRECT
sudo iptables -t nat -C PREROUTING -i ens18 -p udp -j REDIRECT 2>/dev/null || sudo iptables -t nat -A PREROUTING -i ens18 -p udp -j REDIRECT
sudo tcpdump -i ens18 -n -Z remnux -w "$PCAP" 2>/dev/null &
TCPDUMP=$!
trap 'sudo kill $TCPDUMP 2>/dev/null; echo; echo "PCAP saved: $PCAP"; echo "INetSim report: /var/log/inetsim/report/"' EXIT
echo "Redirect active, capturing to $PCAP"
echo "Starting INetSim (Ctrl+C to stop)..."
sudo inetsim 2> >(grep --line-buffered -v "IO/Select.pm line 68" >&2)
```

- `-Z remnux`: tcpdump writes the PCAP as the normal user.
- Only stderr goes through `grep -v` (process substitution). Piping all output (`2>&1 | grep`) makes Perl block-buffer stdout, so INetSim looks stuck at "Forking services..." although it runs.
- The filter hides harmless Perl warnings (`Argument ... isn't numeric in numeric eq (==) at .../IO/Select.pm line 68`) that INetSim prints per received packet on Ubuntu 24.04's Perl. DNS works regardless.

The iptables rules are not persistent; the script re-adds them on every start.

Logs and captures:

- Live: `sudo tail -f /var/log/inetsim/service.log`
- Report after Ctrl+C: `/var/log/inetsim/report/`
- PCAP: `~/captures/<timestamp>.pcap`, open with `wireshark`

## Analysing the capture

Idle Windows generates a lot of Microsoft traffic (updates, telemetry, certificate checks, NCSI, Edge, OneDrive). Since INetSim answers everything with 10.20.20.1, IPs are meaningless; **domain names, URLs and SNI are the IOCs**.

Wireshark display filter (saved as button `IOCs`):

```
(dns.flags.response == 0 || http.request || tls.handshake.type == 1) && !(dns.qry.name matches "(microsoft|windowsupdate|msftconnecttest|msftncsi|windows|live|bing|msn|office|skype|azure|msedge|digicert|trafficmanager|akamai)\.(com|net)$") && !(http.host matches "(microsoft|windowsupdate|msftconnecttest|msftncsi|windows|live|bing|msn|office|skype|azure|msedge|digicert|trafficmanager|akamai)\.(com|net)$") && !(tls.handshake.extensions_server_name matches "(microsoft|windowsupdate|msftconnecttest|msftncsi|windows|live|bing|msn|office|skype|azure|msedge|digicert|trafficmanager|akamai)\.(com|net)$")
```

Optional (not set up yet; NetworkMiner and Wireshark are used instead): quick text IOC list, `~/bin/pcap-iocs.sh [file.pcap]` (default newest capture):

```bash
#!/bin/bash
PCAP="${1:-$(ls -t ~/captures/*.pcap | head -1)}"
NOISE='(microsoft|windowsupdate|msftconnecttest|msftncsi|windows|live|bing|msn|office|skype|azure|msedge|digicert|trafficmanager|akamai)\.(com|net)$'
echo "== DNS queries ($PCAP)"
tshark -r "$PCAP" -Y 'dns.flags.response == 0' -T fields -e dns.qry.name 2>/dev/null | grep -viE "$NOISE" | sort | uniq -c | sort -rn
echo "== HTTP requests"
tshark -r "$PCAP" -Y 'http.request' -T fields -e http.request.method -e http.host -e http.request.uri 2>/dev/null | grep -viE "$NOISE" | sort | uniq -c | sort -rn
echo "== TLS server names"
tshark -r "$PCAP" -Y 'tls.handshake.type == 1' -T fields -e tls.handshake.extensions_server_name 2>/dev/null | grep -viE "$NOISE" | sort | uniq -c | sort -rn
```

Caveat: malware can hide behind Microsoft domains or services (OneDrive, Azure). If a sample looks quiet, check without the filter.

Other tools worth using on PCAPs: NetworkMiner (hosts, files, sessions), Zeek (structured logs), Suricata (`suricata -r file.pcap` with ET Open or own rules). Do not upload sensitive captures to online analysers.

## Snapshots

- 302 `clean` was retaken after adding the capture to the start script.
- Roll back **only 402** after a detonation. Rolling back 302 deletes PCAPs and INetSim reports; 302 only receives fake traffic and does not run samples. Clean up `~/captures/` occasionally.

## Tests

| Test in 402 | Expected | Result |
|---|---|---|
| `ping 10.20.20.1` | reply | Pass |
| `nslookup evil-test-domain.com` | 10.20.20.1 | Pass (after enabling `start_service dns`) |
| `curl.exe http://1.2.3.4/` | INetSim default HTML page (redirect of hardcoded IP) | Pass |
| `curl.exe http://evil-test-domain.com/` | INetSim default HTML page | Pass |
| `ping 8.8.8.8` | no reply | Pass |

## Workflow

1. Start 302, run `detonate-start.sh`.
2. Start 402 from snapshot `clean`.
3. Get the sample into 402 via transfer ISO (see below).
4. Execute, observe with Procmon, Process Explorer, etc.; watch INetSim service.log.
5. Ctrl+C on REMnux, read the report (DNS names, URLs, ports = IOCs).
6. Roll back both to `clean`.

## Sample transfer (301 → host → 402)

402 has no network path to anything. Samples travel as a **read-only ISO** built on the Proxmox host:

```
remnux-work 301 (vmbr1)        Proxmox host                 flare-detonate 402 (vmbr2)
sample.zip in ~/Downloads ──guest agent──► ISO ──virtual CD──► D:\sample.zip
```

- One direction only (CD is read-only), no new network path, sample stays zipped on the host.
- Uses the QEMU guest agent (`qm guest exec`), not the network.
- Limit about 10 MB per file (guest agent output buffer, base64 overhead).

One-time setup in the **Proxmox shell** (node → Shell):

```bash
apt install -y genisoimage jq
qm agent 301 ping && echo "agent OK"   # 301 must be running; else: sudo apt install qemu-guest-agent in 301
```

`/root/bin/sample2iso.sh`:

```bash
#!/bin/bash
# Usage: sample2iso.sh <file-in-301> [target-vmid]
set -euo pipefail
SRC="$1"; TARGET="${2:-402}"; SRCVM=301
ISO="/var/lib/vz/template/iso/sample-transfer.iso"
TMP=$(mktemp -d)
OUT=$(qm guest exec "$SRCVM" --timeout 120 -- base64 -w0 "$SRC")
if ! echo "$OUT" | jq -e '.exitcode==0 and ((."out-truncated")|not)' >/dev/null; then
  echo "Copy failed:"; echo "$OUT" | jq '{exitcode, "err-data", "out-truncated"}'; rm -rf "$TMP"; exit 1
fi
echo "$OUT" | jq -r '."out-data"' | base64 -d > "$TMP/$(basename "$SRC")"
echo "SHA256 on host:"; sha256sum "$TMP/$(basename "$SRC")"
genisoimage -quiet -J -R -V SAMPLE -o "$ISO" "$TMP"
rm -rf "$TMP"
qm set "$TARGET" --ide2 local:iso/sample-transfer.iso,media=cdrom >/dev/null
echo "ISO attached to VM $TARGET as CD drive."
```

`/root/bin/sample-clean.sh`:

```bash
#!/bin/bash
TARGET="${1:-402}"
qm set "$TARGET" --ide2 none,media=cdrom >/dev/null
rm -f /var/lib/vz/template/iso/sample-transfer.iso
echo "Transfer ISO removed."
```

Per sample:

1. In 301: download the zip from your sample source to `~/Downloads`, `sha256sum ~/Downloads/<file>.zip`.
2. Proxmox shell: `/root/bin/sample2iso.sh /home/remnux/Downloads/<file>.zip` (hash must match).
3. In 402: copy from the CD drive to the desktop, extract with 7-Zip.
4. Afterwards: roll back 402 to `clean`, then `/root/bin/sample-clean.sh`.

Tested with a test file: works.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| REMnux boot hangs at `systemd-networkd-wait-online` | Waits for DHCP, none on vmbr2 | Wait ~2 min, then disable and mask the service |
| `nmcli` profile created but not applied, ens18 `unmanaged` | ens18 managed by systemd-networkd via netplan | Use netplan file instead, delete NM profile |
| HTTP to random IP works, DNS times out | INetSim DNS service disabled (`#start_service dns`) | Enable it, restart INetSim, check `ss -lunp \| grep ':53 '` |
