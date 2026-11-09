#!/usr/bin/env python3
"""leak-hunter: inventory, text extraction and keyword hunting for leak data.

Local web UI (default http://127.0.0.1:8090). Python 3 standard library plus
command line tools: 7z, ripgrep (rg), pdftotext, readpst, mdb-tables/mdb-export.

Files are only read by parsers, never opened or executed.

Layout:
  LH_DOCS/<case>/            source files of a case (shared with Datashare)
  LH_WORK/<case>/index.db    inventory
  LH_WORK/<case>/text/       extracted text of converted documents
  LH_WORK/<case>/extracted/  contents of archives, mailboxes, attachments
  LH_WORK/<case>/lists/      keyword lists (JSON)
  LH_WORK/<case>/reports/    HTML and CSV reports

UI: ui.html next to this file (single page, JSON API under /api/).
"""
import base64
import concurrent.futures
import csv
import hashlib
import html
import io
import json
import mailbox
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
import threading
import time
import traceback
import urllib.parse
import xml.etree.ElementTree as ET
import zipfile
from email import policy
from email.parser import BytesParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DOCS = os.environ.get("LH_DOCS", "/cases/datashare/docs")
WORK = os.environ.get("LH_WORK", "/cases/leak-hunter")
BIND = os.environ.get("LH_BIND", "127.0.0.1")
PORT = int(os.environ.get("LH_PORT", "8090"))
WORKERS = int(os.environ.get("LH_WORKERS", "4"))

MAX_TEXT = 256 * 1024 ** 2          # max extracted text per file
MAX_STRINGS_INPUT = 64 * 1024 ** 2  # strings fallback only for files up to this size
MAX_DEPTH = 6                       # archive nesting
DISK_RESERVE = 5 * 1024 ** 3        # keep free on /cases
HTML_MAX_PER_FILE = 200
HTML_MAX_TOTAL = 20000
SNIP = 150

CSRF = secrets.token_urlsafe(24)
JOB = {"running": False}
JOB_LOCK = threading.Lock()

TEXT_EXT = set("""txt csv tsv log json jsonl ndjson xml sql md ini cfg conf config yaml yml env
ps1 psm1 sh bash bat cmd py js ts php asp aspx jsp java c cpp h cs go rb pl vbs htm html xhtml
css rtf vcf ics ldif reg properties toml dat out bak sav lst txt~""".split())
MEDIA_EXT = set("""jpg jpeg png gif bmp tif tiff webp heic ico svgz mp3 wav flac aac ogg m4a
mp4 mkv avi mov wmv flv webm mpg mpeg exe dll sys msi so dylib bin iso img vmdk vhd vhdx
ttf otf woff woff2 class pyc o a""".split())
OOXML_EXT = {"docx", "docm", "dotx", "xlsx", "xlsm", "xltx", "pptx", "pptm", "potx", "vsdx"}
ODF_EXT = {"odt", "ods", "odp", "odg"}
ARCHIVE_EXT = {"zip", "7z", "rar", "tar", "gz", "tgz", "bz2", "tbz2", "xz", "txz", "cab",
               "zst", "lz", "lzma", "jar", "apk", "war", "001"}
EXPECTED = {  # extension -> kinds that are plausible, else flagged as mismatch
    "pdf": {"pdf"}, "zip": {"archive", "ooxml", "odf"}, "7z": {"archive"}, "rar": {"archive"},
    "docx": {"ooxml"}, "xlsx": {"ooxml"}, "pptx": {"ooxml"}, "doc": {"ole"}, "xls": {"ole"},
    "ppt": {"ole"}, "msg": {"ole"}, "jpg": {"media"}, "jpeg": {"media"}, "png": {"media"},
    "gif": {"media"}, "txt": {"text"}, "csv": {"text"}, "pst": {"pst"}, "ost": {"pst"},
    "sqlite": {"sqlite"}, "db": {"sqlite", "binary", "ole"}, "mdb": {"mdb"}, "accdb": {"mdb"},
}


# ---------------------------------------------------------------- helpers

def safe_name(s):
    return re.sub(r"[^A-Za-z0-9._-]", "_", s).strip("._")[:80]


def case_dir(case):
    return os.path.join(WORK, case)


def db_path(case):
    return os.path.join(case_dir(case), "index.db")


def connect(case):
    con = sqlite3.connect(db_path(case), timeout=30)
    con.execute("PRAGMA journal_mode=WAL")
    return con


def list_cases():
    try:
        return sorted(d for d in os.listdir(DOCS)
                      if os.path.isdir(os.path.join(DOCS, d)) and not d.startswith("."))
    except FileNotFoundError:
        return []


def valid_case(case):
    return case in list_cases()


def human(n):
    n = float(n or 0)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or u == "TB":
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024


def free_bytes():
    os.makedirs(WORK, exist_ok=True)
    return shutil.disk_usage(WORK).free


def job_set(**kw):
    with JOB_LOCK:
        JOB.update(kw)


def ext_of(name):
    n = name.lower()
    for double in (".tar.gz", ".tar.bz2", ".tar.xz"):
        if n.endswith(double):
            return double[1:]
    return n.rsplit(".", 1)[1] if "." in os.path.basename(n) else ""


def sniff(path, ext):
    try:
        with open(path, "rb") as f:
            head = f.read(8192)
    except OSError:
        return "unreadable"
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        if ext in OOXML_EXT:
            return "ooxml"
        if ext in ODF_EXT:
            return "odf"
        return "archive"
    if head.startswith((b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07", b"\x1f\x8b", b"BZh",
                        b"\xfd7zXZ\x00", b"MSCF", b"\x28\xb5\x2f\xfd")):
        return "archive"
    if len(head) > 262 and head[257:262] == b"ustar":
        return "archive"
    if head.startswith(b"%PDF"):
        return "pdf"
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"
    if head.startswith(b"SQLite format 3\x00"):
        return "sqlite"
    if head.startswith(b"!BDN"):
        return "pst"
    if head[4:19] in (b"Standard Jet DB", b"Standard ACE DB"):
        return "mdb"
    if ext == "eml":
        return "eml"
    if ext == "mbox" or (ext in ("", "mbx") and head.startswith(b"From ")):
        return "mbox"
    if ext in MEDIA_EXT:
        return "media"
    if ext in TEXT_EXT:
        return "text"
    if head.startswith((b"\xff\xfe", b"\xfe\xff", b"\xef\xbb\xbf")):
        return "text"
    if head and b"\x00" not in head:
        return "text"
    if not head:
        return "empty"
    return "binary"


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


class TextOut:
    """Writes extracted text with a size cap."""

    def __init__(self, path):
        self.path = path
        self.f = open(path, "w", encoding="utf-8", errors="replace")
        self.n = 0
        self.truncated = False

    def line(self, s):
        if self.truncated:
            return False
        s = s.replace("\r", " ").replace("\n", " ")
        self.n += len(s) + 1
        if self.n > MAX_TEXT:
            self.truncated = True
            return False
        self.f.write(s + "\n")
        return True

    def close(self):
        self.f.close()


def local(tag):
    return tag.rsplit("}", 1)[-1]


def xml_paragraphs(stream, para_tags):
    """Yield one line per paragraph-like element (docx w:p, pptx a:p, odf text:p)."""
    for _, el in ET.iterparse(stream, events=("end",)):
        if local(el.tag) in para_tags:
            t = "".join(el.itertext()).strip()
            if t:
                yield t
            el.clear()


def strings_lines(path):
    with open(path, "rb") as f:
        data = f.read(MAX_STRINGS_INPUT)
    for m in re.finditer(rb"[\x20-\x7e\t]{6,}", data):
        yield m.group().decode("ascii", "replace")
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){6,}", data):
        yield m.group().decode("utf-16-le", "replace")


def strip_html(s):
    s = re.sub(r"(?is)<(script|style).*?</\1>", " ", s)
    s = re.sub(r"(?s)<[^>]+>", " ", s)
    return html.unescape(s)


def run(cmd, timeout):
    return subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=timeout)


def sanitize_tree(root):
    """Remove symlinks and anything resolving outside root (zip-slip, link tricks)."""
    real_root = os.path.realpath(root)
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            p = os.path.join(dirpath, name)
            if os.path.islink(p) or not os.path.realpath(p).startswith(real_root + os.sep):
                try:
                    os.unlink(p) if not os.path.isdir(p) or os.path.islink(p) else shutil.rmtree(p)
                except OSError:
                    pass


def walk_children(root, display_prefix):
    out = []
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            p = os.path.join(dirpath, name)
            if os.path.isfile(p) and not os.path.islink(p):
                rel = os.path.relpath(p, root)
                out.append((display_prefix + rel, p))
    return out


# ---------------------------------------------------------------- per-file processing

def process(case, row, opts):
    """Returns dict of column updates and a list of children (display, real)."""
    fid, display, real, depth = row
    upd = {"status": "ok", "note": "", "text": None}
    children = []
    base = case_dir(case)
    try:
        st = os.stat(real)
        ext = ext_of(display)
        kind = sniff(real, ext)
        upd.update(size=st.st_size, ext=ext, kind=kind)
        exp = EXPECTED.get(ext)
        upd["mismatch"] = 1 if exp and kind not in exp else 0
        if opts.get("hash"):
            upd["sha256"] = sha256_file(real)
        txt_path = os.path.join(base, "text", f"{fid}.txt")
        sub = os.path.join(base, "extracted", str(fid))

        if kind == "archive":
            if depth >= MAX_DEPTH:
                upd.update(status="skipped", note="max archive depth")
            elif free_bytes() < DISK_RESERVE + 2 * st.st_size:
                upd.update(status="skipped", note="not enough free disk for extraction")
            else:
                ok, note = extract_archive(real, sub, opts.get("passwords", []))
                sanitize_tree(sub)
                children = walk_children(sub, display + "!/")
                upd.update(status="ok" if ok else "error", note=note)
        elif kind == "text":
            upd["text"] = real  # searched in place, line numbers match the original
        elif kind in ("ooxml", "odf", "pdf", "ole", "sqlite", "mdb", "eml", "mbox", "binary"):
            if kind == "binary" and st.st_size > MAX_STRINGS_INPUT:
                upd.update(status="ok", note="binary, too large for strings")
            else:
                out = TextOut(txt_path)
                try:
                    note = EXTRACTORS[kind](real, out, sub, display, children)
                finally:
                    out.close()
                upd["text"] = txt_path
                upd["note"] = (note or "") + (" text truncated" if out.truncated else "")
                if kind == "eml" and os.path.isdir(sub):
                    sanitize_tree(sub)
        elif kind == "pst":
            os.makedirs(sub, exist_ok=True)
            r = run(["readpst", "-q", "-e", "-o", sub, real], 6 * 3600)
            sanitize_tree(sub)
            children = walk_children(sub, display + "!/")
            upd.update(status="ok" if r.returncode == 0 else "error",
                       note=f"{len(children)} items" if r.returncode == 0 else r.stderr.decode(errors="replace")[:200])
        else:
            upd["note"] = "not searched" if kind == "media" else ""
    except subprocess.TimeoutExpired:
        upd.update(status="error", note="timeout")
    except Exception as e:  # keep going, record the problem
        upd.update(status="error", note=f"{type(e).__name__}: {e}"[:300])
    return fid, upd, children


def extract_archive(real, dest, passwords):
    os.makedirs(dest, exist_ok=True)
    tries = ["lh-no-password"] + list(passwords)
    last = ""
    for pw in tries:
        r = run(["7z", "x", "-y", "-bso0", "-bsp0", f"-p{pw}", f"-o{dest}", real], 6 * 3600)
        err = r.stderr.decode(errors="replace")
        if r.returncode == 0:
            return True, "extracted" + (" (password)" if pw != "lh-no-password" else "")
        last = err
        if "password" not in err.lower():
            break
        shutil.rmtree(dest, ignore_errors=True)
        os.makedirs(dest, exist_ok=True)
    if "password" in last.lower():
        return False, "encrypted, no matching password"
    # partial extraction (damaged archive) still yields files
    return False, ("partial: " if os.listdir(dest) else "") + last.strip().splitlines()[-1][:200] if last.strip() else "7z failed"


def ex_ooxml(real, out, sub, display, children):
    with zipfile.ZipFile(real) as z:
        names = z.namelist()
        big = [i for i in z.infolist() if i.file_size > 1024 ** 3]
        if big:
            return "skipped oversized XML part"
        if any(n.startswith("xl/") for n in names):
            shared = []
            if "xl/sharedStrings.xml" in names:
                with z.open("xl/sharedStrings.xml") as f:
                    for _, el in ET.iterparse(f, events=("end",)):
                        if local(el.tag) == "si":
                            shared.append("".join(el.itertext()))
                            el.clear()
            sheets = sorted((n for n in names if re.match(r"xl/worksheets/sheet\d+\.xml$", n)),
                            key=lambda n: int(re.findall(r"\d+", n)[-1]))
            for sn in sheets:
                label = os.path.basename(sn)[:-4]
                with z.open(sn) as f:
                    for _, el in ET.iterparse(f, events=("end",)):
                        if local(el.tag) == "row":
                            cells = []
                            for c in el:
                                if local(c.tag) != "c":
                                    continue
                                t = c.get("t")
                                v = next((x.text for x in c if local(x.tag) == "v"), None)
                                if t == "s" and v is not None and v.isdigit() and int(v) < len(shared):
                                    cells.append(shared[int(v)])
                                elif t == "inlineStr":
                                    cells.append("".join(c.itertext()))
                                elif v is not None:
                                    cells.append(v)
                            if any(cells):
                                if not out.line(f"[{label} row {el.get('r', '?')}] " + " | ".join(cells)):
                                    return None
                            el.clear()
            return None
        if any(n.startswith("ppt/") for n in names):
            parts = sorted((n for n in names if re.match(r"ppt/(slides/slide|notesSlides/notesSlide)\d+\.xml$", n)),
                           key=lambda n: (n.split("/")[1], int(re.findall(r"\d+", n)[-1])))
            for pn in parts:
                label = os.path.basename(pn)[:-4]
                with z.open(pn) as f:
                    for line in xml_paragraphs(f, {"p"}):
                        out.line(f"[{label}] {line}")
            return None
        parts = [n for n in names if n.startswith("word/") and re.search(
            r"(document|header\d*|footer\d*|footnotes|endnotes|comments)\.xml$", n)]
        parts = parts or [n for n in names if n.endswith(".xml")]
        for pn in parts:
            with z.open(pn) as f:
                for line in xml_paragraphs(f, {"p", "tc"} if not pn.startswith("word/") else {"p"}):
                    out.line(line)
    return None


def ex_odf(real, out, sub, display, children):
    with zipfile.ZipFile(real) as z:
        with z.open("content.xml") as f:
            for line in xml_paragraphs(f, {"p", "h"}):
                out.line(line)


def ex_pdf(real, out, sub, display, children):
    tmp = out.path + ".pdf.txt"
    r = run(["pdftotext", "-q", "-enc", "UTF-8", real, tmp], 900)
    if os.path.exists(tmp):
        with open(tmp, encoding="utf-8", errors="replace") as f:
            for line in f:
                if not out.line(line.rstrip("\n")):
                    break
        os.unlink(tmp)
    return None if r.returncode == 0 else "pdftotext errors (encrypted or damaged?)"


def ex_strings(real, out, sub, display, children):
    for s in strings_lines(real):
        if not out.line(s):
            break
    return "strings only"


def ex_sqlite(real, out, sub, display, children):
    uri = "file:" + urllib.parse.quote(real) + "?mode=ro&immutable=1"
    con = sqlite3.connect(uri, uri=True)
    con.text_factory = lambda b: b.decode("utf-8", "replace")
    try:
        tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        for t in tables:
            cols = [r[1] for r in con.execute(f'PRAGMA table_info("{t}")')]
            out.line(f"## table {t}: " + " | ".join(cols))
            for row in con.execute(f'SELECT * FROM "{t}"'):
                vals = ["<blob>" if isinstance(v, bytes) else ("" if v is None else str(v)) for v in row]
                if not out.line(f"[{t}] " + " | ".join(vals)):
                    return None
    finally:
        con.close()
    return None


def ex_mdb(real, out, sub, display, children):
    r = run(["mdb-tables", "-1", real], 300)
    for t in r.stdout.decode(errors="replace").splitlines():
        if not t.strip():
            continue
        out.line(f"## table {t}")
        p = subprocess.Popen(["mdb-export", real, t], stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        for line in p.stdout:
            if not out.line(f"[{t}] " + line.decode("utf-8", "replace").rstrip("\n")):
                p.kill()
                break
        p.wait()
    return None


def write_message(msg, out):
    for h in ("From", "To", "Cc", "Bcc", "Reply-To", "Subject", "Date", "Message-ID"):
        if msg.get(h):
            out.line(f"{h}: {msg.get(h)}")
    for part in msg.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        ctype = part.get_content_type()
        if ctype in ("text/plain", "text/html"):
            try:
                body = part.get_content()
            except Exception:
                body = (part.get_payload(decode=True) or b"").decode("utf-8", "replace")
            if ctype == "text/html":
                body = strip_html(body)
            for line in body.splitlines():
                if line.strip() and not out.line(line):
                    return


def ex_eml(real, out, sub, display, children):
    with open(real, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)
    write_message(msg, out)
    n = 0
    for part in msg.iter_attachments():
        data = part.get_payload(decode=True)
        if not data:
            continue
        n += 1
        os.makedirs(sub, exist_ok=True)
        name = safe_name(part.get_filename() or f"attachment{n}") or f"attachment{n}"
        p = os.path.join(sub, f"{n:03d}_{name}")
        with open(p, "wb") as f:
            f.write(data)
        out.line(f"Attachment: {part.get_filename() or name}")
        children.append((display + "!/" + os.path.basename(p), p))
    return f"{n} attachments" if n else None


def ex_mbox(real, out, sub, display, children):
    box = mailbox.mbox(real, factory=lambda f: BytesParser(policy=policy.default).parse(f), create=False)
    n = 0
    for msg in box:
        n += 1
        out.line(f"===== message {n}")
        write_message(msg, out)
        if out.truncated:
            break
    return f"{n} messages (attachments not extracted)"


EXTRACTORS = {"ooxml": ex_ooxml, "odf": ex_odf, "pdf": ex_pdf, "ole": ex_strings,
              "binary": ex_strings, "sqlite": ex_sqlite, "mdb": ex_mdb, "eml": ex_eml,
              "mbox": ex_mbox}


# ---------------------------------------------------------------- jobs

SCHEMA = """
CREATE TABLE IF NOT EXISTS files(
  id INTEGER PRIMARY KEY, path TEXT, real TEXT, parent INTEGER, depth INTEGER,
  ext TEXT, kind TEXT, size INTEGER, sha256 TEXT, text TEXT, status TEXT, note TEXT,
  mismatch INTEGER DEFAULT 0, dir TEXT, name TEXT);
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS dirs(key TEXT PRIMARY KEY, parent TEXT, name TEXT, archive INTEGER,
  nfiles INTEGER, size INTEGER, ndirs INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS runs(id INTEGER PRIMARY KEY, list TEXT, stamp TEXT, base TEXT,
  keywords TEXT, whole_words INTEGER, hits INTEGER DEFAULT 0, files INTEGER DEFAULT 0, done INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS hits(run INTEGER, kw TEXT, fid INTEGER, line INTEGER, snippet TEXT);
CREATE TABLE IF NOT EXISTS flags(fid INTEGER PRIMARY KEY);
"""
INDEXES = """
CREATE INDEX IF NOT EXISTS files_dir ON files(dir);
CREATE INDEX IF NOT EXISTS dirs_parent ON dirs(parent);
CREATE INDEX IF NOT EXISTS hits_run_kw ON hits(run, kw);
CREATE INDEX IF NOT EXISTS hits_run_fid ON hits(run, fid);
"""


def split_dir(path):
    """'a/b.zip!/c/d.txt' -> ('a/b.zip!/c/', 'd.txt'). Archive contents use '!/' as separator."""
    i = path.rfind("/")
    return (path[:i + 1], path[i + 1:]) if i >= 0 else ("", path)


def build_tree(con):
    """Folder tree with recursive file counts and sizes. Archives, mailboxes and mails with
    attachments appear as folders named '<file>!'. Archive files themselves are not counted
    in sizes (their contents are)."""
    agg = {"": [0, 0]}
    upd = []
    for fid, path, kind, size in con.execute("SELECT id, path, kind, size FROM files"):
        d, name = split_dir(path)
        upd.append((d, name, fid))
        if kind == "archive":
            continue
        size = size or 0
        agg[""][0] += 1
        agg[""][1] += size
        for m in re.finditer("/", path):
            k = path[:m.end()]
            a = agg.get(k)
            if a is None:
                a = agg[k] = [0, 0]
            a[0] += 1
            a[1] += size
    # make sure every folder exists, even if it only holds archives
    for d, _, _ in upd:
        for m in re.finditer("/", d):
            agg.setdefault(d[:m.end()], [0, 0])
    con.executemany("UPDATE files SET dir=?, name=? WHERE id=?", upd)
    rows = []
    for k, (n, s) in agg.items():
        if k == "":
            rows.append(("", None, "", 0, n, s))
            continue
        parent, seg = split_dir(k[:-1])
        rows.append((k, parent, seg, 1 if seg.endswith("!") else 0, n, s))
    con.executemany("INSERT INTO dirs(key, parent, name, archive, nfiles, size) VALUES(?,?,?,?,?,?)", rows)
    con.execute("UPDATE dirs SET ndirs=(SELECT COUNT(*) FROM dirs d2 WHERE d2.parent=dirs.key)")


def index_job(case, opts):
    base = case_dir(case)
    for d in ("text", "extracted"):
        shutil.rmtree(os.path.join(base, d), ignore_errors=True)
        os.makedirs(os.path.join(base, d), exist_ok=True)
    for sfx in ("", "-wal", "-shm"):
        if os.path.exists(db_path(case) + sfx):
            os.unlink(db_path(case) + sfx)
    con = connect(case)
    con.executescript(SCHEMA)
    src = os.path.join(DOCS, case)
    job_set(phase="listing files")
    for dirpath, _, filenames in os.walk(src):
        for name in filenames:
            p = os.path.join(dirpath, name)
            if os.path.isfile(p) and not os.path.islink(p):
                con.execute("INSERT INTO files(path, real, parent, depth, status) VALUES(?,?,NULL,0,'new')",
                            (os.path.relpath(p, src), p))
    con.commit()
    started = time.time()
    with concurrent.futures.ThreadPoolExecutor(WORKERS) as pool:
        while True:
            rows = con.execute("SELECT id, path, real, depth FROM files WHERE status='new' LIMIT 256").fetchall()
            if not rows:
                break
            con.executemany("UPDATE files SET status='busy' WHERE id=?", [(r[0],) for r in rows])
            depth_of = {r[0]: r[3] for r in rows}
            for fid, upd, children in pool.map(lambda r: process(case, r, opts), rows):
                cols = ", ".join(f"{k}=?" for k in upd)
                con.execute(f"UPDATE files SET {cols} WHERE id=?", list(upd.values()) + [fid])
                con.executemany("INSERT INTO files(path, real, parent, depth, status) VALUES(?,?,?,?,'new')",
                                [(d, r, fid, depth_of[fid] + 1) for d, r in children])
            con.commit()
            done, total = con.execute("SELECT SUM(status NOT IN ('new','busy')), COUNT(*) FROM files").fetchone()
            job_set(phase="processing", done=done, total=total)
    job_set(phase="building folder tree")
    build_tree(con)
    con.executescript(INDEXES)
    con.execute("INSERT OR REPLACE INTO meta VALUES('indexed', ?)", (time.strftime("%Y-%m-%d %H:%M"),))
    con.execute("INSERT OR REPLACE INTO meta VALUES('duration_s', ?)", (str(int(time.time() - started)),))
    con.commit()
    job_set(phase="writing overview report")
    overview_report(case, con)
    con.close()


def parse_keywords(raw):
    """Comma, semicolon or newline separated. Lines starting with re: are one regex each."""
    out, seen = [], set()
    for line in raw.replace("\r", "").split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [line] if line.lower().startswith("re:") else re.split(r"[,;\t]", line)
        for p in parts:
            p = p.strip().strip('"').strip("'").strip()
            if len(p) < 2 or p.lower() in seen:
                continue
            if p.lower().startswith("re:"):
                try:
                    re.compile(p[3:])
                except re.error:
                    continue
            seen.add(p.lower())
            out.append(p)
    return out


def lists_dir(case):
    return os.path.join(case_dir(case), "lists")


def load_lists(case):
    res = []
    d = lists_dir(case)
    if os.path.isdir(d):
        for n in sorted(os.listdir(d)):
            if n.endswith(".json"):
                with open(os.path.join(d, n), encoding="utf-8") as f:
                    res.append(json.load(f))
    return res


def load_list(case, name):
    p = os.path.join(lists_dir(case), safe_name(name) + ".json")
    if os.path.exists(p):
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    return None


def snippet(line_b, subs):
    """line_b bytes, subs list of (start, end) byte offsets -> HTML with <mark>."""
    s0 = max(0, subs[0][0] - SNIP)
    e0 = min(len(line_b), subs[0][1] + SNIP)
    parts, pos = [], s0
    for s, e in subs:
        if s < pos or e > e0:
            continue
        parts.append(html.escape(line_b[pos:s].decode("utf-8", "replace")))
        parts.append("<mark>" + html.escape(line_b[s:e].decode("utf-8", "replace")) + "</mark>")
        pos = e
    parts.append(html.escape(line_b[pos:e0].decode("utf-8", "replace")))
    pre = "&hellip;" if s0 > 0 else ""
    post = "&hellip;" if e0 < len(line_b) else ""
    plain = line_b[s0:e0].decode("utf-8", "replace")
    return pre + "".join(parts) + post, plain


def rg_matches(targets, args, words, max_per_file=None, deadline=None, stop=None):
    """Yield (path, line_number, line_bytes, [(start, end, text)]) from ripgrep."""
    batch = 500
    for i in range(0, len(targets), batch):
        cmd = ["rg", "--json", "-a", "-i", "--no-ignore", "--hidden", "--no-messages", "--no-config"]
        if words:
            cmd.append("-w")
        if max_per_file:
            cmd += ["-m", str(max_per_file)]
        cmd += args + ["--"] + targets[i:i + batch]
        p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            for raw in p.stdout:
                if (deadline and time.time() > deadline) or (stop and stop()):
                    return
                try:
                    ev = json.loads(raw)
                except ValueError:
                    continue
                if ev.get("type") != "match":
                    continue
                d = ev["data"]
                lines = d["lines"]
                lb = lines["text"].encode("utf-8") if "text" in lines else base64.b64decode(lines.get("bytes", ""))
                subs = [(s["start"], s["end"], s["match"].get("text", "")) for s in d["submatches"]]
                yield d["path"].get("text"), d["line_number"], lb.rstrip(b"\r\n"), subs
        finally:
            if p.poll() is None:
                p.kill()
            p.wait()
        yield None  # batch boundary (progress)


def hunt_job(case, name):
    kl = load_list(case, name)
    kws = kl["keywords"]
    words = kl.get("whole_words", False)
    con = connect(case)
    con.executescript(SCHEMA + INDEXES)
    files, by_text = {}, {}
    for fid, path, kind, size, sha, text in con.execute(
            "SELECT id, path, kind, size, sha256, text FROM files"):
        files[fid] = (path, kind, size, sha)
        if text:
            by_text.setdefault(text, fid)
    rep = os.path.join(case_dir(case), "reports")
    os.makedirs(rep, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    base = f"{safe_name(name)}_{stamp}"
    run_id = con.execute("INSERT INTO runs(list, stamp, base, keywords, whole_words) VALUES(?,?,?,?,?)",
                         (name, time.strftime("%Y-%m-%d %H:%M"), base, json.dumps(kws), int(words))).lastrowid
    con.commit()
    stats = {k: {"hits": 0, "files": set()} for k in kws}
    samples, pending = {}, []
    shown = 0
    fixed = [k for k in kws if not k.lower().startswith("re:")]
    regexes = [k for k in kws if k.lower().startswith("re:")]
    lookup = {k.lower(): k for k in fixed}

    csvf = open(os.path.join(rep, base + ".csv"), "w", newline="", encoding="utf-8")
    w = csv.writer(csvf)
    w.writerow(["list", "keyword", "where", "file", "kind", "size", "sha256", "line", "snippet"])

    def flush():
        con.executemany("INSERT INTO hits(run, kw, fid, line, snippet) VALUES(?,?,?,?,?)", pending)
        pending.clear()
        con.commit()

    def record(kw, fid, line, html_snip, plain):
        nonlocal shown
        st = stats[kw]
        st["hits"] += 1
        st["files"].add(fid)
        path, kind, size, sha = files[fid]
        w.writerow([name, kw, "content" if line else "filename", path, kind, size, sha or "", line or "", plain])
        pending.append((run_id, kw, fid, line, plain))
        if len(pending) >= 5000:
            flush()
        lst = samples.setdefault(fid, [])
        if len(lst) < HTML_MAX_PER_FILE and shown < HTML_MAX_TOTAL:
            lst.append((kw, line, html_snip))
            shown += 1

    job_set(phase="matching file names")
    for fid, (path, *_rest) in files.items():
        low = path.lower()
        for k in fixed:
            hit = re.search(r"\b" + re.escape(k.lower()) + r"\b", low) if words else (k.lower() in low)
            if hit:
                record(k, fid, None, html.escape(path), path)
        for k in regexes:
            if re.search(k[3:], path, re.I):
                record(k, fid, None, html.escape(path), path)

    targets = list(by_text.keys())
    passes = []
    pat = os.path.join(case_dir(case), f".patterns_{stamp}")
    if fixed:
        with open(pat, "w", encoding="utf-8") as f:
            f.write("\n".join(fixed) + "\n")
        passes.append((["-F", "-f", pat], None))
    for k in regexes:
        passes.append((["-e", k[3:]], k))
    for pi, (args, fixed_kw) in enumerate(passes):
        done = 0
        job_set(phase=f"searching contents (pass {pi + 1}/{len(passes)})", done=0, total=len(targets))
        for m in rg_matches(targets, args, words):
            if m is None:
                done = min(done + 500, len(targets))
                job_set(done=done)
                continue
            pth, line_no, lb, subs = m
            fid = by_text.get(pth)
            if fid is None:
                continue
            per_kw = {}
            for s, e, mt in subs:
                kw = fixed_kw or lookup.get(mt.lower()) or next((k for k in fixed if k.lower() in mt.lower()), None)
                if kw:
                    per_kw.setdefault(kw, []).append((s, e))
            for kw, sl in per_kw.items():
                h, plain = snippet(lb, sl)
                record(kw, fid, line_no, h, plain)
    flush()
    csvf.close()
    if os.path.exists(pat):
        os.unlink(pat)
    total = sum(s["hits"] for s in stats.values())
    nfiles = len(set().union(*[s["files"] for s in stats.values()])) if stats else 0
    con.execute("UPDATE runs SET hits=?, files=?, done=1 WHERE id=?", (total, nfiles, run_id))
    con.commit()
    con.close()
    job_set(phase="writing report")
    write_hunt_html(case, name, kl, base, stats, samples, files, shown)


CSS = """body{font:14px/1.45 system-ui,sans-serif;margin:24px;color:#1b1f24;background:#fff}
h1{font-size:22px}h2{font-size:17px;margin-top:28px}table{border-collapse:collapse;width:100%;margin:8px 0}
th,td{border:1px solid #d0d7de;padding:4px 8px;text-align:left;vertical-align:top}th{background:#f6f8fa}
td.n{text-align:right;white-space:nowrap;width:1%}td.kw{white-space:nowrap;width:1%}mark{background:#ffe066}code,.mono{font-family:ui-monospace,monospace;font-size:12px}
.muted{color:#656d76}.file{margin-top:16px;padding:8px;border:1px solid #d0d7de;border-radius:6px}
.warn{background:#fff8c5;padding:8px;border:1px solid #d4a72c;border-radius:6px}
@media print{.file{break-inside:avoid}}"""


def page_doc(title, body):
    return (f"<!doctype html><html><head><meta charset='utf-8'>"
            f"<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'\">"
            f"<title>{html.escape(title)}</title><style>{CSS}</style></head><body>{body}</body></html>")


def write_hunt_html(case, name, kl, base, stats, samples, files, shown):
    e = html.escape
    total = sum(s["hits"] for s in stats.values())
    nfiles = len(set().union(*[s["files"] for s in stats.values()])) if stats else 0
    b = [f"<h1>Keyword report: {e(name)}</h1>",
         f"<p class='muted'>Case <b>{e(case)}</b> &middot; generated {time.strftime('%Y-%m-%d %H:%M')} &middot; "
         f"{len(kl['keywords'])} keywords &middot; whole words: {'yes' if kl.get('whole_words') else 'no'} &middot; "
         f"{total} hits in {nfiles} files</p>",
         "<p class='muted'>This report contains only hits for this keyword list. "
         "The CSV next to this file contains every hit. Line: line in the original file for text files, "
         "line of the extracted text for documents (paragraph, table row, mail line). "
         "<code>!/</code> marks a path inside an archive, mailbox or mail attachment.</p>"]
    if shown >= HTML_MAX_TOTAL or any(len(v) >= HTML_MAX_PER_FILE for v in samples.values()):
        b.append(f"<p class='warn'>HTML shows at most {HTML_MAX_PER_FILE} hits per file and "
                 f"{HTML_MAX_TOTAL} in total. See <code>{e(base)}.csv</code> for all hits.</p>")
    b.append("<h2>Summary per keyword</h2><table><tr><th>Keyword</th><th>Hits</th><th>Files</th></tr>")
    for k in sorted(stats, key=lambda k: -stats[k]["hits"]):
        s = stats[k]
        b.append(f"<tr><td><code>{e(k)}</code></td><td class='n'>{s['hits']}</td><td class='n'>{len(s['files'])}</td></tr>")
    b.append("</table>")
    if samples:
        b.append("<h2>Files with hits</h2><table><tr><th>File</th><th>Kind</th><th>Size</th><th>Hits shown</th></tr>")
        order = sorted(samples, key=lambda f: -len(samples[f]))
        for fid in order:
            path, kind, size, sha = files[fid]
            b.append(f"<tr><td class='mono'>{e(path)}</td><td>{e(kind or '')}</td>"
                     f"<td class='n'>{human(size)}</td><td class='n'>{len(samples[fid])}</td></tr>")
        b.append("</table><h2>Hits</h2>")
        for fid in order:
            path, kind, size, sha = files[fid]
            b.append(f"<div class='file'><div class='mono'><b>{e(path)}</b></div>"
                     f"<div class='muted mono'>{e(kind or '')} &middot; {human(size)} &middot; SHA256 {e(sha or 'n/a')}</div>"
                     "<table><tr><th>Keyword</th><th>Line</th><th>Context</th></tr>")
            for kw, line, h in samples[fid]:
                b.append(f"<tr><td class='kw'><code>{e(kw)}</code></td><td class='n'>{line or 'name'}</td><td class='mono'>{h}</td></tr>")
            b.append("</table></div>")
    else:
        b.append("<p>No hits.</p>")
    with open(os.path.join(case_dir(case), "reports", base + ".html"), "w", encoding="utf-8") as f:
        f.write(page_doc(f"{name} - {case}", "".join(b)))


def overview_report(case, con):
    e = html.escape
    rep = os.path.join(case_dir(case), "reports")
    os.makedirs(rep, exist_ok=True)
    with open(os.path.join(rep, "inventory.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["path", "kind", "ext", "size", "sha256", "depth", "status", "note", "ext_mismatch"])
        for r in con.execute("SELECT path, kind, ext, size, sha256, depth, status, note, mismatch FROM files ORDER BY path"):
            w.writerow(r)
    q = lambda s, *a: con.execute(s, a).fetchall()
    n, size = q("SELECT COUNT(*), SUM(size) FROM files WHERE kind!='archive' OR kind IS NULL")[0]
    narch = q("SELECT COUNT(*) FROM files WHERE kind='archive'")[0][0]
    searchable = q("SELECT COUNT(*) FROM files WHERE text IS NOT NULL")[0][0]
    meta = dict(q("SELECT k, v FROM meta"))
    b = [f"<h1>Case overview: {e(case)}</h1>",
         f"<p class='muted'>Indexed {e(meta.get('indexed', '?'))} in {e(meta.get('duration_s', '?'))} s</p>",
         "<table>",
         f"<tr><th>Files (without archives)</th><td class='n'>{n}</td></tr>",
         f"<tr><th>Total size</th><td class='n'>{human(size)}</td></tr>",
         f"<tr><th>Archives (incl. nested)</th><td class='n'>{narch}</td></tr>",
         f"<tr><th>Searchable files</th><td class='n'>{searchable}</td></tr></table>",
         "<h2>By kind</h2><table><tr><th>Kind</th><th>Files</th><th>Size</th></tr>"]
    for k, c, s in q("SELECT kind, COUNT(*), SUM(size) FROM files GROUP BY kind ORDER BY 2 DESC"):
        b.append(f"<tr><td>{e(k or '?')}</td><td class='n'>{c}</td><td class='n'>{human(s)}</td></tr>")
    b.append("</table><h2>By extension (top 50)</h2><table><tr><th>Extension</th><th>Files</th><th>Size</th></tr>")
    for x, c, s in q("SELECT ext, COUNT(*), SUM(size) FROM files GROUP BY ext ORDER BY 2 DESC LIMIT 50"):
        b.append(f"<tr><td>{e(x or '(none)')}</td><td class='n'>{c}</td><td class='n'>{human(s)}</td></tr>")
    b.append("</table><h2>Top folders</h2><table><tr><th>Folder</th><th>Files</th><th>Size</th></tr>")
    folders = {}
    for p, s in q("SELECT path, size FROM files WHERE depth=0"):
        top = p.split("/")[0] if "/" in p else "(root)"
        f = folders.setdefault(top, [0, 0])
        f[0] += 1
        f[1] += s or 0
    for top, (c, s) in sorted(folders.items(), key=lambda x: -x[1][1])[:30]:
        b.append(f"<tr><td class='mono'>{e(top)}</td><td class='n'>{c}</td><td class='n'>{human(s)}</td></tr>")
    b.append("</table><h2>Largest files</h2><table><tr><th>File</th><th>Kind</th><th>Size</th></tr>")
    for p, k, s in q("SELECT path, kind, size FROM files ORDER BY size DESC LIMIT 25"):
        b.append(f"<tr><td class='mono'>{e(p)}</td><td>{e(k or '')}</td><td class='n'>{human(s)}</td></tr>")
    b.append("</table>")
    mm = q("SELECT path, ext, kind FROM files WHERE mismatch=1 LIMIT 200")
    if mm:
        b.append("<h2>Extension does not match content</h2><table><tr><th>File</th><th>Extension</th><th>Detected</th></tr>")
        for p, x, k in mm:
            b.append(f"<tr><td class='mono'>{e(p)}</td><td>{e(x)}</td><td>{e(k)}</td></tr>")
        b.append("</table>")
    errs = q("SELECT path, status, note FROM files WHERE status IN ('error','skipped') LIMIT 500")
    if errs:
        b.append("<h2>Problems (encrypted, damaged, skipped)</h2><table><tr><th>File</th><th>Status</th><th>Note</th></tr>")
        for p, s, nt in errs:
            b.append(f"<tr><td class='mono'>{e(p)}</td><td>{e(s)}</td><td>{e(nt or '')}</td></tr>")
        b.append("</table>")
    b.append("<p class='muted'>Full list: <code>inventory.csv</code></p>")
    with open(os.path.join(rep, "overview.html"), "w", encoding="utf-8") as f:
        f.write(page_doc(f"Overview - {case}", "".join(b)))


def start_job(kind, case, target, *args):
    with JOB_LOCK:
        if JOB.get("running"):
            return False
        JOB.clear()
        JOB.update(running=True, kind=kind, case=case, phase="starting", done=0, total=0,
                   started=time.time(), error=None)

    def runner():
        try:
            target(case, *args)
            job_set(phase="finished")
        except Exception:
            job_set(error=traceback.format_exc()[-1500:])
        finally:
            job_set(running=False, ended=time.time())

    threading.Thread(target=runner, daemon=True).start()
    return True


# ---------------------------------------------------------------- JSON API


def has_index(case):
    if not os.path.exists(db_path(case)):
        return False
    try:
        con = connect(case)
        ok = con.execute("SELECT v FROM meta WHERE k='indexed'").fetchone() is not None
        con.close()
        return ok
    except sqlite3.Error:
        return False


def q_all(con, sql, args=()):
    cur = con.execute(sql, args)
    cols = [c[0] for c in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


def api_status():
    with JOB_LOCK:
        j = dict(JOB)
    if j.get("started"):
        j["elapsed"] = int((j.get("ended") if not j.get("running") and j.get("ended") else time.time()) - j["started"])
    cases = []
    for c in list_cases():
        st = index_stats(c)
        cases.append({"name": c, "files": st[0] if st else None, "size": st[1] if st else None,
                      "indexed": st[2] if st else None})
    return {"job": j, "cases": cases, "free": free_bytes(), "docs": DOCS, "work": WORK}


def index_stats(case):
    if not os.path.exists(db_path(case)):
        return None
    try:
        con = sqlite3.connect(db_path(case), timeout=5)
        n, s = con.execute("SELECT COUNT(*), SUM(size) FROM files WHERE kind IS NOT 'archive'").fetchone()
        meta = dict(con.execute("SELECT k, v FROM meta").fetchall())
        con.close()
        return n, s, meta.get("indexed")
    except sqlite3.Error:
        return None


def api_overview(case):
    if not has_index(case):
        return {"indexed": False}
    con = connect(case)
    one = lambda s, a=(): con.execute(s, a).fetchone()
    meta = dict(con.execute("SELECT k, v FROM meta").fetchall())
    n, size = one("SELECT COUNT(*), COALESCE(SUM(size),0) FROM files WHERE kind IS NOT 'archive'")
    res = {
        "indexed": True, "meta": meta,
        "totals": {
            "files": n, "size": size,
            "archives": one("SELECT COUNT(*) FROM files WHERE kind='archive'")[0],
            "archive_size": one("SELECT COALESCE(SUM(size),0) FROM files WHERE kind='archive' AND depth=0")[0],
            "searchable": one("SELECT COUNT(*) FROM files WHERE text IS NOT NULL")[0],
            "problems": one("SELECT COUNT(*) FROM files WHERE status IN ('error','skipped')")[0],
            "mismatches": one("SELECT COUNT(*) FROM files WHERE mismatch=1")[0],
            "mails": one("SELECT COUNT(*) FROM files WHERE kind='eml'")[0],
            "max_depth": one("SELECT COALESCE(MAX(depth),0) FROM files")[0],
            "folders": one("SELECT COUNT(*) FROM dirs WHERE archive=0 AND key!=''")[0],
        },
        "kinds": q_all(con, "SELECT kind, COUNT(*) files, COALESCE(SUM(size),0) size FROM files "
                            "GROUP BY kind ORDER BY size DESC"),
        "exts": q_all(con, "SELECT COALESCE(NULLIF(ext,''),'(none)') ext, COUNT(*) files, COALESCE(SUM(size),0) size "
                           "FROM files WHERE kind IS NOT 'archive' GROUP BY 1 ORDER BY size DESC LIMIT 60"),
        "top": q_all(con, "SELECT key, name, archive, nfiles, size FROM dirs WHERE parent='' ORDER BY size DESC LIMIT 25"),
        "largest": q_all(con, "SELECT id, path, dir, kind, size FROM files WHERE kind IS NOT 'archive' "
                              "ORDER BY size DESC LIMIT 25"),
        "problems": q_all(con, "SELECT id, path, dir, kind, status, note FROM files WHERE status IN ('error','skipped') "
                               "ORDER BY path LIMIT 300"),
        "mismatches": q_all(con, "SELECT id, path, dir, ext, kind FROM files WHERE mismatch=1 ORDER BY path LIMIT 200"),
    }
    con.close()
    return res


def api_tree(case, key, offset, sort, dirs_only):
    con = connect(case)
    node = q_all(con, "SELECT key, parent, name, archive, nfiles, size, ndirs FROM dirs WHERE key=?", (key,))
    if not node:
        con.close()
        return {"error": "unknown folder"}
    res = {"node": node[0],
           "dirs": q_all(con, "SELECT key, name, archive, nfiles, size, ndirs FROM dirs WHERE parent=? "
                              "ORDER BY size DESC, name LIMIT 5000", (key,))}
    if not dirs_only:
        order = {"size": "f.size DESC", "kind": "f.kind, f.name", "name": "f.name COLLATE NOCASE"}.get(sort, "f.name COLLATE NOCASE")
        res["nfiles_here"] = con.execute("SELECT COUNT(*) FROM files WHERE dir=?", (key,)).fetchone()[0]
        res["files"] = q_all(con, "SELECT f.id, f.name, f.kind, f.ext, f.size, f.status, f.note, f.mismatch, f.sha256, "
                                  "f.real, (f.text IS NOT NULL) searchable, d.key child "
                                  "FROM files f LEFT JOIN dirs d ON d.key = f.path || '!/' "
                                  f"WHERE f.dir=? ORDER BY {order} LIMIT 200 OFFSET ?", (key, offset))
    con.close()
    return res


def api_view(case, fid, line, ctx):
    con = connect(case)
    r = con.execute("SELECT path, real, text, kind FROM files WHERE id=?", (fid,)).fetchone()
    con.close()
    if not r or not r[2]:
        return {"error": "no text for this file"}
    path, real, text, kind = r
    start = max(1, line - ctx) if line else 1
    end = (line + ctx) if line else 200
    out = []
    with open(text, encoding="utf-8", errors="replace") as f:
        for n, l in enumerate(f, 1):
            if n < start:
                continue
            if n > end:
                break
            l = l.rstrip("\r\n")
            out.append([n, l[:4000] + (" [...]" if len(l) > 4000 else "")])
    return {"path": path, "real": real, "kind": kind, "converted": text != real,
            "line": line, "start": start, "lines": out}


def hit_filter(p):
    where, args = ["h.run=?"], [int(p.get("run") or 0)]
    if p.get("kws") not in (None, ""):
        kws = json.loads(p["kws"])
        if not kws:
            where.append("0")
        else:
            where.append("h.kw IN (%s)" % ",".join("?" * len(kws)))
            args += kws
    if p.get("q"):
        where.append("(lower(f.path) LIKE ? OR lower(h.snippet) LIKE ?)")
        args += ["%" + p["q"].lower() + "%"] * 2
    if p.get("flagged") == "1":
        where.append("h.fid IN (SELECT fid FROM flags)")
    return " AND ".join(where), args


HIT_COLS = ("SELECT h.kw, h.fid, h.line, h.snippet, f.path, f.real, f.kind, f.size, f.sha256, "
            "(fl.fid IS NOT NULL) flagged FROM hits h JOIN files f ON f.id=h.fid LEFT JOIN flags fl ON fl.fid=h.fid ")


def api_hits(case, p):
    con = connect(case)
    w, a = hit_filter(p)
    page = int(p.get("page") or 0)
    nh, nf = con.execute(f"SELECT COUNT(*), COUNT(DISTINCT h.fid) FROM hits h JOIN files f ON f.id=h.fid WHERE {w}", a).fetchone()
    res = {"hits": nh, "files": nf, "page": page, "per_page": 100}
    if p.get("view") == "files":
        rows = q_all(con, "SELECT h.fid, f.path, f.real, f.kind, f.size, COUNT(*) n, COUNT(DISTINCT h.kw) nk, "
                          "GROUP_CONCAT(DISTINCT h.kw) kws, (SELECT 1 FROM flags WHERE fid=h.fid) flagged "
                          f"FROM hits h JOIN files f ON f.id=h.fid WHERE {w} GROUP BY h.fid "
                          "ORDER BY nk DESC, n DESC LIMIT 100 OFFSET ?", a + [page * 100])
        for r in rows:
            r["sub"] = q_all(con, f"SELECT h.kw, h.line, h.snippet FROM hits h JOIN files f ON f.id=h.fid "
                                  f"WHERE {w} AND h.fid=? ORDER BY h.rowid LIMIT 30", a + [r["fid"]])
        res["rows"] = rows
    else:
        res["rows"] = q_all(con, HIT_COLS + f"WHERE {w} ORDER BY h.rowid LIMIT 100 OFFSET ?", a + [page * 100])
    con.close()
    return res


def export_html(title, case, rows, info):
    e = html.escape
    kws, files = {}, {}
    for r in rows:
        k = kws.setdefault(r["kw"], [0, set()])
        k[0] += 1
        k[1].add(r["fid"])
        fe = files.setdefault(r["fid"], {"path": r["path"], "kind": r["kind"], "size": r["size"], "sha": r["sha256"],
                                         "kws": set(), "n": 0, "flag": r["flagged"]})
        fe["kws"].add(r["kw"])
        fe["n"] += 1
    terms = [k[3:] if k.lower().startswith("re:") else re.escape(k) for k in kws]
    rx = re.compile("(" + "|".join(terms) + ")", re.I) if terms else None

    def hl(s):
        s = s or ""
        if not rx:
            return e(s)
        out, pos = [], 0
        for m in rx.finditer(s):
            if m.end() == m.start():
                continue
            out.append(e(s[pos:m.start()]) + "<mark>" + e(m.group()) + "</mark>")
            pos = m.end()
        return "".join(out) + e(s[pos:])

    b = [f"<h1>{e(title)}</h1><p class='muted'>Case <b>{e(case)}</b> &middot; generated {time.strftime('%Y-%m-%d %H:%M')}"
         f"<br>{e(info)}<br>{len(rows)} hits in {len(files)} files</p>",
         "<h2>Summary per keyword</h2><table><tr><th>Keyword</th><th>Hits</th><th>Files</th></tr>"]
    for k, (n, fs) in sorted(kws.items(), key=lambda x: -x[1][0]):
        b.append(f"<tr><td class='kw'><code>{e(k)}</code></td><td class='n'>{n}</td><td class='n'>{len(fs)}</td></tr>")
    b.append("</table><h2>Files</h2><table><tr><th>File</th><th>Keywords</th><th>Hits</th><th>Flag</th></tr>")
    for f in sorted(files.values(), key=lambda f: (-len(f["kws"]), -f["n"])):
        b.append(f"<tr><td class='mono'>{e(f['path'])}<div class='muted'>{e(f['kind'] or '')} &middot; {human(f['size'])}"
                 f" &middot; SHA256 {e(f['sha'] or 'n/a')}</div></td><td>{e(', '.join(sorted(f['kws'])))}</td>"
                 f"<td class='n'>{f['n']}</td><td>{'&#9733;' if f['flag'] else ''}</td></tr>")
    b.append("</table><h2>All hits</h2><table><tr><th>Keyword</th><th>File</th><th>Line</th><th>Context</th></tr>")
    for r in rows:
        b.append(f"<tr><td class='kw'><code>{e(r['kw'])}</code></td><td class='mono'>{e(r['path'])}</td>"
                 f"<td class='n'>{r['line'] or 'name'}</td><td class='mono'>{hl(r['snippet'])}</td></tr>")
    b.append("</table>")
    return page_doc(title, "".join(b))


def api_export(case, p):
    con = connect(case)
    w, a = hit_filter(p)
    rows = q_all(con, HIT_COLS + f"WHERE {w} ORDER BY h.rowid LIMIT 2000000", a)
    run = con.execute("SELECT list, stamp FROM runs WHERE id=?", (int(p.get("run") or 0),)).fetchone()
    con.close()
    lst = run[0] if run else "run"
    info = f"List {lst} (run {run[1] if run else '?'})" + (f" | text filter \"{p['q']}\"" if p.get("q") else "") + \
           (" | flagged files only" if p.get("flagged") == "1" else "")
    stamp = time.strftime("%Y%m%d-%H%M")
    fmt = p.get("fmt")
    if fmt == "csv":
        buf = io.StringIO()
        wr = csv.writer(buf)
        wr.writerow(["keyword", "file", "kind", "size", "sha256", "line", "snippet", "flagged", "real_path"])
        for r in rows:
            wr.writerow([r["kw"], r["path"], r["kind"], r["size"], r["sha256"] or "", r["line"] or "", r["snippet"],
                         "yes" if r["flagged"] else "", r["real"]])
        return f"{safe_name(lst)}_filtered_{stamp}.csv", "﻿" + buf.getvalue(), "text/csv; charset=utf-8"
    if fmt == "zip":
        by = {}
        for r in rows:
            by.setdefault(r["kw"], []).append(r)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for k, rs in by.items():
                z.writestr(f"{safe_name(lst)}_{safe_name(k) or 'regex'}_{stamp}.html",
                           export_html(f"Keyword report: {k}", case, rs, info + f" | keyword {k}"))
        return f"{safe_name(lst)}_per_keyword_{stamp}.zip", buf.getvalue(), "application/zip"
    return (f"{safe_name(lst)}_filtered_{stamp}.html", export_html(f"Keyword report: {lst}", case, rows, info),
            "text/html; charset=utf-8")


def api_search(case, p):
    q = (p.get("q") or "").strip()
    if len(q) < 2:
        return {"error": "enter at least 2 characters"}
    regex = p.get("mode") == "regex"
    if regex:
        try:
            rx = re.compile(q, re.I)
        except re.error as ex:
            return {"error": f"invalid regex: {ex}"}
    words = p.get("words") == "1"
    limit = min(int(p.get("limit") or 500), 5000)
    con = connect(case)
    t0 = time.time()
    results = []
    truncated = False
    if p.get("scope") == "names":
        if regex:
            for fid, path, kind, size, real in con.execute("SELECT id, path, kind, size, real FROM files"):
                if rx.search(path):
                    results.append({"fid": fid, "path": path, "kind": kind, "size": size, "real": real, "line": None, "snippet": path})
                    if len(results) >= limit:
                        truncated = True
                        break
        else:
            results = q_all(con, "SELECT id fid, path, kind, size, real, NULL line, path snippet FROM files "
                                 "WHERE lower(path) LIKE ? ORDER BY path LIMIT ?", ("%" + q.lower() + "%", limit + 1))
            truncated = len(results) > limit
            results = results[:limit]
    else:
        files = {}
        for fid, path, kind, size, real, text in con.execute("SELECT id, path, kind, size, real, text FROM files WHERE text IS NOT NULL"):
            files.setdefault(text, (fid, path, kind, size, real))
        args = ["-e", q] if regex else ["-F", "-e", q]
        deadline = time.time() + 120
        for m in rg_matches(list(files), args, words, max_per_file=20, deadline=deadline,
                            stop=lambda: len(results) >= limit):
            if m is None:
                continue
            pth, line_no, lb, subs = m
            f = files.get(pth)
            if not f or not subs:
                continue
            _, plain = snippet(lb, [(s, e) for s, e, _ in subs])
            results.append({"fid": f[0], "path": f[1], "kind": f[2], "size": f[3], "real": f[4],
                            "line": line_no, "snippet": plain})
        truncated = len(results) >= limit or time.time() > deadline
    con.close()
    return {"results": results, "truncated": truncated, "seconds": round(time.time() - t0, 1)}


def api_reports(case):
    rep = os.path.join(case_dir(case), "reports")
    if not os.path.isdir(rep):
        return []
    out = []
    for f in sorted(os.listdir(rep), reverse=True):
        if f.endswith(".html") and f != "overview.html":
            out.append({"html": f, "csv": f[:-5] + ".csv"})
    return out


def api_runs(case):
    if not os.path.exists(db_path(case)):
        return []
    con = connect(case)
    try:
        return q_all(con, "SELECT id, list, stamp, hits, files, done FROM runs ORDER BY id DESC")
    except sqlite3.Error:
        return []
    finally:
        con.close()


def api_kw(case, run):
    con = connect(case)
    rows = q_all(con, "SELECT kw, COUNT(*) hits, COUNT(DISTINCT fid) files FROM hits WHERE run=? GROUP BY kw "
                      "ORDER BY hits DESC", (run,))
    r = con.execute("SELECT keywords FROM runs WHERE id=?", (run,)).fetchone()
    con.close()
    seen = {x["kw"] for x in rows}
    for k in json.loads(r[0]) if r else []:
        if k not in seen:
            rows.append({"kw": k, "hits": 0, "files": 0})
    return rows


# ---------------------------------------------------------------- web UI

with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "ui.html"), encoding="utf-8") as _f:
    UI_HTML = _f.read()


class Handler(BaseHTTPRequestHandler):
    server_version = "leak-hunter"

    def log_message(self, fmt, *args):
        pass

    def send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def json(self, obj, code=200):
        self.send(code, json.dumps(obj, default=str), "application/json; charset=utf-8")

    def host_ok(self):
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0]
        return host in ("127.0.0.1", "localhost")

    def redirect(self, url):
        self.send_response(303)
        self.send_header("Location", url)
        self.end_headers()

    def do_GET(self):
        if not self.host_ok():
            return self.send(403, "forbidden")
        u = urllib.parse.urlparse(self.path)
        p = {k: v[0] for k, v in urllib.parse.parse_qs(u.query, keep_blank_values=True).items()}
        case = p.get("case", "")
        if u.path == "/":
            nonce = secrets.token_urlsafe(16)
            csp = (f"default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-{nonce}'; "
                   "connect-src 'self'; img-src data:; form-action 'self'; base-uri 'none'")
            return self.send(200, UI_HTML.replace("__NONCE__", nonce).replace("__CSRF__", CSRF),
                             extra={"Content-Security-Policy": csp})
        if u.path == "/api/status":
            return self.json(api_status())
        if u.path.startswith("/api/") and not valid_case(case):
            return self.json({"error": "unknown case"}, 404)
        try:
            if u.path == "/api/overview":
                return self.json(api_overview(case))
            if u.path == "/api/tree":
                if not has_index(case):
                    return self.json({"error": "not indexed"})
                return self.json(api_tree(case, p.get("key", ""), int(p.get("offset") or 0), p.get("sort", "name"),
                                          p.get("dirs_only") == "1"))
            if u.path == "/api/view":
                return self.json(api_view(case, int(p.get("id") or 0), int(p.get("line") or 0), int(p.get("ctx") or 25)))
            if u.path == "/api/runs":
                return self.json(api_runs(case))
            if u.path == "/api/kw":
                return self.json(api_kw(case, int(p.get("run") or 0)))
            if u.path == "/api/hits":
                return self.json(api_hits(case, p))
            if u.path == "/api/search":
                if not has_index(case):
                    return self.json({"error": "not indexed"})
                return self.json(api_search(case, p))
            if u.path == "/api/lists":
                return self.json(load_lists(case))
            if u.path == "/api/reports":
                return self.json(api_reports(case))
            if u.path == "/api/export":
                name, body, ctype = api_export(case, p)
                return self.send(200, body, ctype, {"Content-Disposition": f"attachment; filename={name}"})
        except (sqlite3.Error, ValueError, OSError) as ex:
            return self.json({"error": f"{type(ex).__name__}: {ex}"}, 500)
        if u.path == "/file" and valid_case(case):
            name = p.get("name", "")
            if re.fullmatch(r"[A-Za-z0-9._-]+\.(html|csv)", name):
                fp = os.path.join(case_dir(case), "reports", name)
                if os.path.isfile(fp):
                    with open(fp, "rb") as fh:
                        data = fh.read()
                    if name.endswith(".csv"):
                        return self.send(200, data, "text/csv; charset=utf-8",
                                         {"Content-Disposition": f"attachment; filename={name}"})
                    return self.send(200, data, extra={
                        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'"})
        return self.send(404, "not found")

    def do_POST(self):
        if not self.host_ok():
            return self.send(403, "forbidden")
        n = int(self.headers.get("Content-Length") or 0)
        if n > 20 * 1024 * 1024:
            return self.send(413, "too large")
        form = urllib.parse.parse_qs(self.rfile.read(n).decode("utf-8", "replace"), keep_blank_values=True)
        f = lambda k: form.get(k, [""])[0]
        if f("csrf") != CSRF:
            return self.send(403, "bad token, reload the page")
        case = f("case")
        if not valid_case(case):
            return self.send(404, "unknown case")
        q = urllib.parse.quote(case)
        back = lambda msg, tab="lists": self.redirect(f"/?case={q}&tab={tab}&msg=" + urllib.parse.quote(msg))
        os.makedirs(case_dir(case), exist_ok=True)
        path = self.path
        if path == "/api/flag":
            fid = int(f("fid") or 0)
            con = connect(case)
            if con.execute("SELECT 1 FROM flags WHERE fid=?", (fid,)).fetchone():
                con.execute("DELETE FROM flags WHERE fid=?", (fid,))
                on = False
            else:
                con.execute("INSERT INTO flags VALUES(?)", (fid,))
                on = True
            con.commit()
            con.close()
            return self.json({"flagged": on})
        if path == "/api/clearflags":
            con = connect(case)
            con.execute("DELETE FROM flags")
            con.commit()
            con.close()
            return self.json({"ok": True})
        if path == "/index":
            pw = [x for x in f("passwords").replace("\r", "").split("\n") if x.strip()]
            ok = start_job("index", case, index_job, {"passwords": pw, "hash": f("hash") == "1"})
            return back("Indexing started" if ok else "Another job is running")
        if path == "/savelist":
            name = safe_name(f("list"))
            kws = parse_keywords(f("keywords"))
            if not name or not kws:
                return back("Name and at least one keyword needed")
            os.makedirs(lists_dir(case), exist_ok=True)
            with open(os.path.join(lists_dir(case), name + ".json"), "w", encoding="utf-8") as fh:
                json.dump({"name": name, "keywords": kws, "whole_words": f("whole_words") == "1"}, fh, indent=1)
            return back(f"Saved list {name} with {len(kws)} keywords")
        if path == "/dellist":
            fp = os.path.join(lists_dir(case), safe_name(f("list")) + ".json")
            if os.path.exists(fp):
                os.unlink(fp)
            return back("List deleted")
        if path == "/hunt":
            name = safe_name(f("list"))
            if not load_list(case, name):
                return back("Unknown list")
            if not has_index(case):
                return back("Index the case first")
            ok = start_job("hunt " + name, case, hunt_job, name)
            return back("Hunt started, results appear in the Hits tab" if ok else "Another job is running", "hits")
        if path == "/purge":
            if f("confirm") != case:
                return back("Case name did not match, nothing deleted")
            if JOB.get("running") and JOB.get("case") == case:
                return back("A job is running on this case")
            shutil.rmtree(case_dir(case), ignore_errors=True)
            return self.redirect("/")
        return self.send(404, "not found")


def main():
    os.makedirs(WORK, exist_ok=True)
    for tool in ("7z", "rg", "pdftotext"):
        if not shutil.which(tool):
            print(f"warning: {tool} not found")
    srv = ThreadingHTTPServer((BIND, PORT), Handler)
    print(f"leak-hunter on http://{BIND}:{PORT}  docs={DOCS}  work={WORK}")
    srv.serve_forever()


if __name__ == "__main__":
    main()
