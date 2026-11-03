# 11 FLARE-VM (Windows) template

Windows 10 22H2 Pro with Mandiant FLARE-VM for Windows malware analysis and reverse engineering.

| VM | ID | Notes |
|---|---|---|
| `flarevm-build` | 9001 | Build VM, keeps snapshots `pre-flare` (clean Windows) and `flare-complete` |
| `flarevm` | 9011 | **Template** (full clone of 9001 after cleanup) |
| `flare-work` | 401 | Linked clone of 9011, snapshot `clean` |

## ISOs

| ISO | Source | How |
|---|---|---|
| `Win10_22H2_English_x64v1.iso` | Microsoft Windows 10 download page | Uploaded via local → ISO Images → Upload |
| `virtio-win.iso` | `https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso` | Download from URL |

Notes:

- Windows 10 instead of 11: no TPM/Secure Boot requirement, local account easy, FLARE-VM docs point to Windows 10.
- Edition must be **Pro** (or Enterprise), not Home (Group Policy needed) and not an "N" edition.
- No product key, runs unactivated.
- To get the direct ISO link from Microsoft on a Windows PC: browser F12, Ctrl+Shift+M (device mode), reload. Link is valid 24 h.

## VM settings

| Tab | Setting |
|---|---|
| General | ID `9001`, name `flarevm` |
| OS | Win10 ISO, type Microsoft Windows 10/2016/2019, additional drive `virtio-win.iso` |
| System | Machine `q35`, BIOS OVMF (UEFI), EFI disk on `nvme`, VirtIO SCSI single, QEMU agent on, no TPM |
| Disks | SCSI, `nvme`, 100 GB, discard + SSD emulation |
| CPU | 4 cores, type `host` |
| Memory | 8192 MB, ballooning off |
| Network | VirtIO, `vmbr1`, firewall off |
| Display | **VirtIO-GPU**, Clipboard VNC (resolution selectable in Windows) |

## Windows install

1. Start, Console, press a key at "Press any key to boot from CD or DVD" (only a few seconds, else Reset).
2. English, keyboard of your choice, Install now, "I don't have a product key", Windows 10 Pro, Custom install.
3. Disk not listed: **Load driver** → virtio-win CD → `vioscsi\w10\amd64` → Red Hat VirtIO SCSI pass-through controller.
4. OOBE without network (no NIC driver yet): "I don't have internet" → "Continue with limited setup".
5. Local user **`analyst`** (no spaces or special characters, required by FLARE-VM). All privacy settings off.
6. On the desktop: run `virtio-win-guest-tools.exe` from the virtio CD (drivers, QEMU guest agent). Network comes up with a `10.10.10.x` address.

## Clipboard (Windows)

- Proxmox: Display Default, Clipboard VNC, full shutdown and start.
- The virtio-win guest tools agent synced only once per service restart. Installed the latest **spice-guest-tools** (`spice-space.org/download/windows/spice-guest-tools/spice-guest-tools-latest.exe`).
- That leaves **two** agent services. Only one may run: `Spice Agent` set to **Disabled**, `SPICE VDAgent` **Automatic/Running**.
- Quirk: copy something inside the VM first, then pasting from the noVNC clipboard box works.
- PowerShell console: paste with right-click.
- Fallback button (restarts the old agent): `net stop vdservice & net start vdservice` as admin.

## Preparation for FLARE-VM

1. **Tamper Protection off** (GUI first, otherwise policies are ignored): Windows Security → Virus & threat protection → Manage settings → Tamper Protection, Real-time, Cloud-delivered, Sample submission all off.
2. `gpedit.msc` → Computer Configuration → Administrative Templates → Windows Components:

| Path | Setting | Value |
|---|---|---|
| Microsoft Defender Antivirus | Turn off Microsoft Defender Antivirus | Enabled |
| Microsoft Defender Antivirus → Real-time Protection | Turn off real-time protection | Enabled |
| Windows Update | Configure Automatic Updates | Disabled |

3. Admin PowerShell:

```powershell
powercfg /change standby-timeout-ac 0
powercfg /change monitor-timeout-ac 0
gpupdate /force
Restart-Computer
```

4. Verify (all `False`, or the command errors because Defender is fully off):

```powershell
Get-MpComputerStatus | Select-Object AMServiceEnabled, RealTimeProtectionEnabled, IsTamperProtected
```

5. Snapshot **`pre-flare`**.

## FLARE-VM install

Admin PowerShell:

```powershell
cd $env:USERPROFILE\Desktop
(New-Object net.webclient).DownloadFile('https://raw.githubusercontent.com/mandiant/flare-vm/main/install.ps1',"$([Environment]::GetFolderPath("Desktop"))\install.ps1")
Unblock-File .\install.ps1; Set-ExecutionPolicy Unrestricted -Force; .\install.ps1
```

- Checks: confirm snapshot with `Y`, enter Windows password (auto-logon during reboots).
- Package selection: default (recommended) set kept, including `dotnet3.5` and `vcredist-all`.
- The OK button was hidden behind the taskbar at 1280x800: press Enter, auto-hide the taskbar, or Alt+Space → M → Up.
- Runtime 1 to 2 hours with several reboots, all downloads via Proton.

## Install result

The installer finished ("Install Complete!") with 15 failed packages. Retries:

| Package(s) | Cause | Result |
|---|---|---|
| asar, js-beautify, js-deobfuscator, malware-jail, obfuscator-io-deobfuscator, pkg-unpacker | Node.js ExperimentalWarning on stderr treated as error | **Installed** after `$env:NODE_NO_WARNINGS = "1"` in the same admin session |
| vscode.extension.python, vscode.extension.jupyter | Transient | Installed on retry |
| sysinternals | Download repeatedly cut off (26 %, 78 %, 80 %) | **Installed manually** with resumable curl (below) to `C:\Tools\sysinternals`, added to PATH |
| recaf, vb-decompiler-lite | Checksum mismatch (upstream file changed) | Skipped (would need `--ignore-checksums`) |
| ezviewer | 404, removed upstream | Skipped |
| angr, regcool | Unclear, niche | Skipped |

Retry command used:

```powershell
$env:NODE_NO_WARNINGS = "1"
choco install -y asar.vm js-beautify.vm js-deobfuscator.vm malware-jail.vm obfuscator-io-deobfuscator.vm pkg-unpacker.vm angr.vm regcool.vm vb-decompiler-lite.vm vscode.extension.jupyter.vm
```

Resumable download (Chocolatey cannot resume):

```powershell
$zip = "$env:USERPROFILE\Downloads\SysinternalsSuite.zip"
do { curl.exe -L -C - --retry 10 --retry-delay 3 -o $zip https://download.sysinternals.com/files/SysinternalsSuite.zip } until ($LASTEXITCODE -eq 0)
Expand-Archive $zip -DestinationPath C:\Tools\sysinternals -Force
[Environment]::SetEnvironmentVariable("Path", [Environment]::GetEnvironmentVariable("Path","Machine") + ";C:\Tools\sysinternals", "Machine")
```

JavaScript analysis is also covered on REMnux.

Logs: `C:\ProgramData\_VM\log.txt`, `C:\ProgramData\chocolatey\logs\chocolatey.log`.

## Resolution

- Default display: Windows resolution greyed out. Fix via UEFI: Esc at boot → EFI Firmware Setup → Device Manager → OVMF Platform Configuration → Change Preferred Resolution → Commit Changes and Exit → Reset.
- Better: Display **VirtIO-GPU** (driver from virtio-win guest tools). Resolution then selectable in Windows Display settings, clipboard still works.
- Alternative without changes: noVNC side panel → Settings → Scaling Mode → Local Scaling.

## To do

- [x] Verify install, retry failed packages
- [x] Resolution (VirtIO-GPU)
- [x] Snapshot `flare-complete`
- [x] MTU/MSS on OPNsense PROTON interface (see [06](06-firewall-rules.md))
- [x] Template 9011 via full clone (9001 has snapshots), linked clone `flare-work` (401), snapshot `clean`
- [ ] Decide detonation network (vmbr1 with Proton internet vs. offline `vmbr2`)
- [ ] Sysprep: skipped on purpose (breaks FLARE-VM setups easily; isolated lab, Proxmox gives clones new MACs so no DHCP collision)

## Template structure and updates

Proxmox refuses to convert a VM with snapshots into a template ("unable to create template, because VM contains snapshots"). So:

- **9001 `flarevm-build`** stays a normal VM with its snapshots. `pre-flare` allows reinstalling FLARE-VM without reinstalling Windows.
- **9011 `flarevm`** is a full clone of 9001, converted to template.

Cleanup before cloning (no `machine-id` equivalent needed: Proxmox gives clones new MACs, Windows DHCP uses the MAC; identical computer names are cosmetic):

```powershell
Remove-Item "$env:USERPROFILE\Downloads\*", "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
Clear-RecycleBin -Force -ErrorAction SilentlyContinue
Stop-Computer
```

Updating the template (new tools, fixes):

1. Start 9001, make changes, cleanup, shut down, optional new snapshot.
2. Remove linked clones of 9011 (e.g. 401), remove 9011.
3. Full clone 9001 → 9011 `flarevm`, convert to template.
4. Linked clone 401 `flare-work`, test, snapshot `clean`.

Per case: work in 401, roll back to `clean` afterwards.
