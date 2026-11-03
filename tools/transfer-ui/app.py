#!/usr/bin/env python3
"""Sample Transfer UI for the analysis lab.

Runs on the Proxmox host as root. Lists files in the source VM's Downloads folder
(via the QEMU guest agent), packs a chosen file into a read-only ISO and attaches it
to a target VM. Also shows VM status, starts VMs and rolls back detonation VMs.

Standard library only. Config: /etc/sample-transfer/config.json (optional).
Set the login once with:  python3 app.py --set-password
"""
import base64
import getpass
import hashlib
import hmac
import html
import ipaddress
import json
import os
import secrets
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

CONFIG_PATH = "/etc/sample-transfer/config.json"
AUTH_PATH = "/etc/sample-transfer/auth"

DEFAULTS = {
    "bind": "0.0.0.0",  # set to the Proxmox host IP in config.json
    "port": 8443,
    "allowed_networks": ["192.168.0.0/16"],  # restrict to your home LAN in config.json
    "source_vm": 301,
    "source_dir": "/home/remnux/Downloads",
    "targets": [402, 302],
    "status_vms": [301, 302, 402],
    "rollback_vms": {"402": "clean"},
    "max_bytes": 10 * 1024 * 1024,
    "iso_dir": "/var/lib/vz/template/iso",
    "iso_storage": "local",
    "cert": "/etc/pve/local/pve-ssl.pem",
    "key": "/etc/pve/local/pve-ssl.key",
}

CFG = dict(DEFAULTS)
CSRF = secrets.token_urlsafe(32)
LOG = deque(maxlen=60)
ACTION_LOCK = threading.Lock()


# ---------------------------------------------------------------- helpers

def log(level, msg):
    LOG.appendleft((time.strftime("%H:%M:%S"), level, msg))
    print(f"[{level}] {msg}", flush=True)


def run(cmd, timeout=60):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def pvesh_json(path, *args):
    rc, out, err = run(["pvesh", "get", path, *args, "--output-format", "json"], timeout=30)
    if rc != 0:
        raise RuntimeError(err.strip() or f"pvesh {path} failed")
    return json.loads(out or "null")


def vm_info():
    """vmid -> {name, status, node, template}"""
    res = pvesh_json("/cluster/resources", "--type", "vm")
    return {int(r["vmid"]): r for r in res if r.get("type") == "qemu"}


def snapshots(node, vmid):
    try:
        return [s["name"] for s in pvesh_json(f"/nodes/{node}/qemu/{vmid}/snapshot") if s.get("name") != "current"]
    except Exception:
        return []


def vm_config(vmid):
    rc, out, err = run(["qm", "config", str(vmid)], timeout=30)
    if rc != 0:
        raise RuntimeError(err.strip() or f"qm config {vmid} failed")
    cfg = {}
    for line in out.splitlines():
        if ": " in line:
            k, v = line.split(": ", 1)
            cfg[k.strip()] = v.strip()
    return cfg


def guest_exec(vmid, args, timeout=60):
    rc, out, err = run(["qm", "guest", "exec", str(vmid), "--timeout", str(timeout), "--", *args],
                       timeout=timeout + 15)
    if rc != 0:
        raise RuntimeError(err.strip() or "guest agent not reachable")
    data = json.loads(out)
    if data.get("out-truncated"):
        raise RuntimeError("guest output truncated (file too large for guest agent)")
    if data.get("exitcode", 1) != 0:
        raise RuntimeError((data.get("err-data") or f"exit code {data.get('exitcode')}").strip())
    return data.get("out-data", "")


def list_source_files():
    src, d = CFG["source_vm"], CFG["source_dir"]
    files = {}
    out = guest_exec(src, ["find", d, "-maxdepth", "1", "-type", "f", "-printf", "%s\\t%f\\n"])
    for line in out.splitlines():
        if "\t" not in line:
            continue
        size, name = line.split("\t", 1)
        if "/" in name or not name:
            continue
        files[name] = {"size": int(size), "sha256": ""}
    if files:
        out = guest_exec(src, ["find", d, "-maxdepth", "1", "-type", "f", "-exec", "sha256sum", "--", "{}", "+"],
                         timeout=120)
        for line in out.splitlines():
            if line.startswith("\\") or "  " not in line:
                continue
            h, path = line.split("  ", 1)
            name = os.path.basename(path)
            if name in files:
                files[name]["sha256"] = h
    return dict(sorted(files.items(), key=lambda kv: kv[0].lower()))


def iso_name(vmid):
    return f"sample-transfer-{vmid}.iso"


def iso_path(vmid):
    return os.path.join(CFG["iso_dir"], iso_name(vmid))


def human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


# ---------------------------------------------------------------- actions

def act_send(name, target):
    if target not in CFG["targets"]:
        raise ValueError(f"VM {target} is not an allowed target")
    files = list_source_files()
    if name not in files:
        raise ValueError(f"File not found in VM {CFG['source_vm']}: {name}")
    meta = files[name]
    if meta["size"] > CFG["max_bytes"]:
        raise ValueError(f"{name} is {human(meta['size'])}, limit is {human(CFG['max_bytes'])}")
    info = vm_info().get(target)
    if not info:
        raise ValueError(f"VM {target} does not exist")
    cfg = vm_config(target)
    if "ide2" not in cfg and info.get("status") == "running":
        raise ValueError(f"VM {target} has no CD drive (ide2). Shut it down once and retry, the drive is added then.")

    data = guest_exec(CFG["source_vm"], ["base64", "-w0", os.path.join(CFG["source_dir"], name)], timeout=120)
    raw = base64.b64decode(data, validate=True)
    digest = hashlib.sha256(raw).hexdigest()
    if meta["sha256"] and digest != meta["sha256"]:
        raise RuntimeError(f"Hash mismatch for {name}: guest {meta['sha256']}, host {digest}")

    tmp = tempfile.mkdtemp(prefix="sample-transfer-")
    try:
        with open(os.path.join(tmp, name), "wb") as f:
            f.write(raw)
        rc, _, err = run(["genisoimage", "-quiet", "-J", "-R", "-V", "SAMPLE", "-o", iso_path(target), tmp], timeout=60)
        if rc != 0:
            raise RuntimeError(f"genisoimage failed: {err.strip()}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    rc, _, err = run(["qm", "set", str(target), "--ide2", f"{CFG['iso_storage']}:iso/{iso_name(target)},media=cdrom"])
    if rc != 0:
        raise RuntimeError(f"Attaching ISO failed: {err.strip()}")
    log("ok", f"Sent {name} ({human(len(raw))}, sha256 {digest}) to VM {target} as CD drive")


def act_clean(target):
    if target not in CFG["targets"]:
        raise ValueError(f"VM {target} is not an allowed target")
    try:
        cfg = vm_config(target)
        if CFG["iso_storage"] + ":iso/" + iso_name(target) in cfg.get("ide2", ""):
            rc, _, err = run(["qm", "set", str(target), "--ide2", "none,media=cdrom"])
            if rc != 0:
                raise RuntimeError(err.strip())
    finally:
        if os.path.exists(iso_path(target)):
            os.remove(iso_path(target))
    log("ok", f"Transfer ISO removed from VM {target} and deleted")


def act_start(vmid):
    if vmid not in CFG["status_vms"]:
        raise ValueError(f"VM {vmid} is not managed here")
    rc, _, err = run(["qm", "start", str(vmid)], timeout=120)
    if rc != 0:
        raise RuntimeError(err.strip() or f"qm start {vmid} failed")
    log("ok", f"VM {vmid} started")


def act_rollback(vmid):
    snap = CFG["rollback_vms"].get(str(vmid))
    if not snap:
        raise ValueError(f"Rollback not allowed for VM {vmid}")
    info = vm_info().get(vmid)
    if not info:
        raise ValueError(f"VM {vmid} does not exist")
    if snap not in snapshots(info["node"], vmid):
        raise ValueError(f"VM {vmid} has no snapshot '{snap}'")
    if info.get("status") == "running":
        rc, _, err = run(["qm", "stop", str(vmid)], timeout=120)
        if rc != 0:
            raise RuntimeError(err.strip() or f"qm stop {vmid} failed")
    rc, _, err = run(["qm", "rollback", str(vmid), snap], timeout=600)
    if rc != 0:
        raise RuntimeError(err.strip() or f"qm rollback {vmid} failed")
    if os.path.exists(iso_path(vmid)):
        os.remove(iso_path(vmid))
    log("ok", f"VM {vmid} rolled back to '{snap}' (stopped). Transfer ISO deleted.")


# ---------------------------------------------------------------- auth

def hash_pw(pw, salt=None, it=200_000):
    salt = salt or secrets.token_bytes(16)
    return salt, it, hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, it)


def load_auth():
    with open(AUTH_PATH) as f:
        user, salt, it, h = f.read().strip().split(":")
    return user, bytes.fromhex(salt), int(it), bytes.fromhex(h)


def set_password():
    user = input("Username [admin]: ").strip() or "admin"
    pw = getpass.getpass("Password: ")
    if len(pw) < 10:
        sys.exit("Use at least 10 characters.")
    if pw != getpass.getpass("Repeat: "):
        sys.exit("Passwords do not match.")
    salt, it, h = hash_pw(pw)
    os.makedirs(os.path.dirname(AUTH_PATH), exist_ok=True)
    fd = os.open(AUTH_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(f"{user}:{salt.hex()}:{it}:{h.hex()}\n")
    print(f"Saved login for '{user}' to {AUTH_PATH}")


# ---------------------------------------------------------------- web

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--fg:#1d2433;--muted:#667085;--line:#e3e6eb;--acc:#2f6fed;--ok:#1a7f37;--warn:#b54708;--err:#c4320a}
@media (prefers-color-scheme:dark){:root{--bg:#12151b;--card:#1b2029;--fg:#e6e9ef;--muted:#98a2b3;--line:#2b3240;--acc:#6b9bff;--ok:#4ac26b;--warn:#f0a14a;--err:#ff7a59}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:980px;margin:0 auto;padding:20px 16px 40px}h1{font-size:20px;margin:0 0 4px}h2{font-size:15px;margin:0 0 10px}
.sub{color:var(--muted);margin:0 0 18px}.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:0 0 16px}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:7px 6px;border-top:1px solid var(--line);vertical-align:middle}
th{color:var(--muted);font-weight:600;border-top:0}td.mono,.mono{font-family:ui-monospace,Consolas,monospace;font-size:12px;word-break:break-all}
.badge{display:inline-block;padding:1px 8px;border-radius:99px;font-size:12px;border:1px solid var(--line)}
.running{color:var(--ok);border-color:var(--ok)}.stopped{color:var(--muted)}
button,select{font:inherit;padding:5px 10px;border-radius:7px;border:1px solid var(--line);background:var(--card);color:var(--fg);cursor:pointer}
button.primary{background:var(--acc);border-color:var(--acc);color:#fff}button.danger{color:var(--err);border-color:var(--err)}
form{display:inline}.row{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
.log td{padding:4px 6px}.log td:first-child{width:80px;white-space:nowrap}.lvl-ok{color:var(--ok)}.lvl-error{color:var(--err)}.lvl-info{color:var(--muted)}
.note{color:var(--warn)}a{color:var(--acc)}@media(max-width:640px){.hide-sm{display:none}}
"""


def esc(s):
    return html.escape(str(s), quote=True)


def form(action, fields, label, cls="", confirm=None):
    hidden = "".join(f'<input type="hidden" name="{esc(k)}" value="{esc(v)}">' for k, v in fields.items())
    onsub = f' onsubmit="return confirm({esc(json.dumps(confirm))})"' if confirm else ""
    return (f'<form method="post" action="/action"{onsub}><input type="hidden" name="csrf" value="{CSRF}">'
            f'<input type="hidden" name="action" value="{esc(action)}">{hidden}'
            f'<button class="{cls}">{esc(label)}</button></form>')


def render():
    parts = [f"<!doctype html><html lang=en><head><meta charset=utf-8>"
             f"<meta name=viewport content='width=device-width,initial-scale=1'><title>Sample Transfer</title>"
             f"<style>{CSS}</style></head><body><main>"
             f"<h1>Sample Transfer</h1><p class=sub>VM {CFG['source_vm']} <span class=mono>{esc(CFG['source_dir'])}</span>"
             f" &rarr; read-only ISO &rarr; target VM &nbsp;·&nbsp; <a href='/'>Refresh</a></p>"]
    try:
        vms = vm_info()
    except Exception as e:
        vms = {}
        parts.append(f"<div class=card><p class=note>Could not read VM status: {esc(e)}</p></div>")

    # VM status
    rows = []
    for vmid in CFG["status_vms"]:
        info = vms.get(vmid)
        if not info:
            rows.append(f"<tr><td>{vmid}</td><td colspan=3 class=note>not found</td></tr>")
            continue
        st = info.get("status", "?")
        btns = []
        if st != "running":
            btns.append(form("start", {"vmid": vmid}, "Start"))
        snap = CFG["rollback_vms"].get(str(vmid))
        if snap:
            if snap in snapshots(info["node"], vmid):
                btns.append(form("rollback", {"vmid": vmid}, f"Roll back to {snap}", "danger",
                                 f"Roll back VM {vmid} to '{snap}'? The VM is stopped and all changes since the snapshot are lost."))
            else:
                btns.append(f"<span class=note>no '{esc(snap)}' snapshot</span>")
        rows.append(f"<tr><td>{vmid}</td><td>{esc(info.get('name', ''))}</td>"
                    f"<td><span class='badge {'running' if st == 'running' else 'stopped'}'>{esc(st)}</span></td>"
                    f"<td><div class=row>{''.join(btns)}</div></td></tr>")
    parts.append("<div class=card><h2>VMs</h2><table><tr><th>ID</th><th>Name</th><th>Status</th><th></th></tr>"
                 + "".join(rows) + "</table></div>")

    # Files
    src = CFG["source_vm"]
    files_html = ""
    if vms.get(src, {}).get("status") != "running":
        files_html = f"<p class=note>VM {src} is not running. Start it to list its Downloads.</p>"
    else:
        try:
            files = list_source_files()
            if not files:
                files_html = "<p>No files in the Downloads folder.</p>"
            else:
                opts = "".join(f"<option value='{t}'>{t} {esc(vms.get(t, {}).get('name', ''))}</option>"
                               for t in CFG["targets"])
                trs = []
                for name, m in files.items():
                    too_big = m["size"] > CFG["max_bytes"]
                    action = ("<span class=note>too large</span>" if too_big else
                              f'<form method="post" action="/action" class=row><input type="hidden" name="csrf" value="{CSRF}">'
                              f'<input type="hidden" name="action" value="send"><input type="hidden" name="name" value="{esc(name)}">'
                              f'<select name="target">{opts}</select><button class="primary">Send</button></form>')
                    trs.append(f"<tr><td class=mono>{esc(name)}</td><td>{human(m['size'])}</td>"
                               f"<td class='mono hide-sm' title='{esc(m['sha256'])}'>{esc(m['sha256'][:16])}{'…' if m['sha256'] else ''}</td>"
                               f"<td>{action}</td></tr>")
                files_html = ("<table><tr><th>File</th><th>Size</th><th class=hide-sm>SHA256</th><th>Send to</th></tr>"
                              + "".join(trs) + "</table>")
        except Exception as e:
            files_html = f"<p class=note>Could not list files: {esc(e)}</p>"
    parts.append(f"<div class=card><h2>Files in VM {src}</h2>{files_html}</div>")

    # Attached ISOs
    isos = [t for t in CFG["targets"] if os.path.exists(iso_path(t))]
    if isos:
        trs = "".join(f"<tr><td>{t}</td><td class=mono>{esc(iso_name(t))}</td><td>{form('clean', {'target': t}, 'Remove and delete')}</td></tr>"
                      for t in isos)
        parts.append(f"<div class=card><h2>Transfer ISOs</h2><table><tr><th>VM</th><th>ISO</th><th></th></tr>{trs}</table></div>")

    # Log
    if LOG:
        trs = "".join(f"<tr><td class=mono>{esc(t)}</td><td class='lvl-{esc(l)}'>{esc(m)}</td></tr>" for t, l, m in LOG)
        parts.append(f"<div class='card log'><h2>Log</h2><table>{trs}</table></div>")
    parts.append("</main></body></html>")
    return "".join(parts)


class Handler(BaseHTTPRequestHandler):
    server_version = "SampleTransfer"
    sys_version = ""

    def log_message(self, fmt, *args):
        pass

    def allowed_ip(self):
        ip = ipaddress.ip_address(self.client_address[0])
        return any(ip in ipaddress.ip_network(n, strict=False) for n in CFG["allowed_networks"])

    def authed(self):
        hdr = self.headers.get("Authorization", "")
        if hdr.startswith("Basic "):
            try:
                user, _, pw = base64.b64decode(hdr[6:]).decode().partition(":")
                auser, salt, it, h = load_auth()
                if hmac.compare_digest(user, auser) and hmac.compare_digest(hash_pw(pw, salt, it)[2], h):
                    return True
            except Exception:
                pass
            time.sleep(1.5)
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Sample Transfer"')
        self.send_header("Content-Length", "0")
        self.end_headers()
        return False

    def guard(self):
        if not self.allowed_ip():
            self.send_error(403)
            return False
        return self.authed()

    def send_page(self, body, code=200):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if not self.guard():
            return
        if self.path != "/":
            self.send_error(404)
            return
        self.send_page(render())

    def do_POST(self):
        if not self.guard():
            return
        if self.path != "/action":
            self.send_error(404)
            return
        length = min(int(self.headers.get("Content-Length", 0) or 0), 10_000)
        q = {k: v[0] for k, v in parse_qs(self.rfile.read(length).decode()).items()}
        if not hmac.compare_digest(q.get("csrf", ""), CSRF):
            log("error", "Rejected request with invalid CSRF token (reload the page)")
        elif not ACTION_LOCK.acquire(blocking=False):
            log("error", "Another action is still running, try again in a moment")
        else:
            try:
                a = q.get("action")
                if a == "send":
                    act_send(q.get("name", ""), int(q.get("target", "0")))
                elif a == "clean":
                    act_clean(int(q.get("target", "0")))
                elif a == "start":
                    act_start(int(q.get("vmid", "0")))
                elif a == "rollback":
                    act_rollback(int(q.get("vmid", "0")))
                else:
                    log("error", f"Unknown action {a!r}")
            except Exception as e:
                log("error", str(e))
            finally:
                ACTION_LOCK.release()
        self.send_response(303)
        self.send_header("Location", "/")
        self.send_header("Content-Length", "0")
        self.end_headers()


def load_config():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH) as f:
            CFG.update(json.load(f))
    CFG["targets"] = [int(x) for x in CFG["targets"]]
    CFG["status_vms"] = [int(x) for x in CFG["status_vms"]]
    CFG["source_vm"] = int(CFG["source_vm"])
    CFG["rollback_vms"] = {str(k): v for k, v in CFG["rollback_vms"].items()}


def main():
    if "--set-password" in sys.argv:
        set_password()
        return
    load_config()
    if not os.path.exists(AUTH_PATH):
        sys.exit(f"No login set. Run: python3 {sys.argv[0]} --set-password")
    srv = ThreadingHTTPServer((CFG["bind"], CFG["port"]), Handler)
    if not os.environ.get("SAMPLE_TRANSFER_NO_TLS"):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(CFG["cert"], CFG["key"])
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    log("info", f"Listening on https://{CFG['bind']}:{CFG['port']}")
    srv.serve_forever()


if __name__ == "__main__":
    main()
