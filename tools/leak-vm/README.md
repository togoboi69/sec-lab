# leak-vm helpers

Scripts for the leak analysis VM (700, see [docs/16](../../docs/16-leak-analysis.md)): unlock the encrypted case volume `/cases`, start Datashare and leak-hunter, and do it right after login.

| File | Installed to | What |
|---|---|---|
| `cases-open` | `/usr/local/bin` | Unlock `/cases` (LUKS), mount it, start Docker, Datashare and leak-hunter. Also works when the desktop already unlocked the disk (mounted under `/media/...`): it is moved to `/cases` |
| `cases-close` | `/usr/local/bin` | Stop leak-hunter, Datashare and Docker, unmount, lock |
| `cases-start` | `/usr/local/bin` | Login starter: runs `cases-open`, waits for leak-hunter, opens http://localhost:8090 in Firefox |
| `cases-start-terminal`, `cases-close-terminal` | `/usr/local/bin` | Open those in the desktop terminal (Ptyxis on Ubuntu 25.10+, else GNOME Terminal) |
| `cases-open.desktop` | `~/.config/autostart` and `~/.local/share/applications` | Runs the starter 5 s after login; app menu entry "Open cases" |
| `cases-close.desktop` | `~/.local/share/applications` | App menu entry "Close cases" |
| `99-hide-cases.rules` (created) | `/etc/udev/rules.d` | Hides the LUKS disk from the dock and Files (`UDISKS_IGNORE`), so it is not unlocked into the wrong place |

## Install (in VM 700, as `analyst`)

Download this repository as ZIP in Firefox in the VM (GitHub: Code → Download ZIP), then:

```bash
cd ~/Downloads && unzip -oq sec-lab-main.zip && bash sec-lab-main/tools/leak-vm/install.sh
rm -rf sec-lab-main sec-lab-main.zip
```

`install.sh` takes the LUKS UUID from the existing `cases-open` (or the first `crypto_LUKS` volume) and writes it into the new script.

## Use

- **Login:** a terminal opens, asks for the sudo password and the LUKS passphrase, then Firefox opens leak-hunter. Skipped or wrong passphrase: app menu → **Open cases** (or `cases-open`).
- **Done:** app menu → **Close cases** (or `cases-close`), then shut down.
- Starting fully automatically at boot is not possible on purpose: the leak data stays encrypted until the passphrase is entered. leak-hunter's service has `ConditionPathIsMountPoint=/cases` and is skipped while `/cases` is locked (`journalctl -u leak-hunter` shows "unmet condition").
- Disable the login prompt: `rm ~/.config/autostart/cases-open.desktop`.
