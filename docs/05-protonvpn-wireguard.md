# 05 Proton VPN WireGuard

WireGuard tunnel to a commercial VPN, terminated on OPNsense. Proton VPN is used as the example; any provider that offers WireGuard config files (e.g. Mullvad, IVPN) works the same way: private key, tunnel address, server public key and endpoint.

## Generate the config

account.protonvpn.com, Downloads, WireGuard configuration:

| Option | Value | Why |
|---|---|---|
| Platform | Router | |
| NetShield | **No filter** | Malware filtering would block the domains we want to analyze |
| Moderate NAT / NAT-PMP | off | |
| VPN Accelerator | off | simpler for router setups |

Store the `.conf` outside this repo. It contains the private key.

Mapping of the `.conf` fields:

```
[Interface]
PrivateKey = ...        -> Instance: Private key
Address = 10.2.0.2/32   -> Instance: Tunnel address
DNS = 10.2.0.1          -> Gateway IP and Unbound forwarder

[Peer]
PublicKey = ...         -> Peer: Public key
AllowedIPs = 0.0.0.0/0  -> Peer: Allowed IPs (IPv4 only)
Endpoint = <IP>:51820   -> Peer: Endpoint address <IP>, port 51820
```

## OPNsense: Instance

VPN, WireGuard, Instances, +

| Field | Value |
|---|---|
| Enabled | yes |
| Name | `proton` |
| Private key | from `.conf` |
| Public key | auto |
| Listen port | empty |
| Tunnel address | `10.2.0.2/32` |
| Disable routes | **yes** (no default route for OPNsense itself, policy routing instead) |
| Gateway | `10.2.0.1` |

## OPNsense: Peer

VPN, WireGuard, Peers, +

| Field | Value |
|---|---|
| Enabled | yes |
| Name | `proton-server` |
| Public key | from `.conf` |
| Allowed IPs | `0.0.0.0/0` |
| Endpoint address / port | from `.conf` / `51820` |
| Instances | `proton` |
| Keepalive | `25` |

There is no separate global "Enable WireGuard" switch in OPNsense 26.x. Instance and peer `Enabled` plus Apply is enough.

Check: VPN, WireGuard, Status shows the peer with a handshake age of a few seconds and bytes in both directions.

## Interface and gateway

Interfaces, Assignments: add `wg0` with description `PROTON`. Then Interfaces, [PROTON]: enable, IPv4 and IPv6 type **None**.

System, Gateways, Configuration, +

| Field | Value |
|---|---|
| Name | `PROTON_GW` |
| Interface | PROTON |
| Address family | IPv4 |
| IP address | `10.2.0.1` |
| Upstream gateway | **no** (WAN stays default for OPNsense itself) |
| Far gateway | **yes** |
| Monitoring | enabled, monitor IP `10.2.0.1` |

Status must show **Online**.

## Changing the Proton server

Generate a new config for another server, then update only: Instance private key and tunnel address (if changed), Peer public key and endpoint. Apply and check the handshake.
