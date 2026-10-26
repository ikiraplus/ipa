#!/usr/bin/env python3
"""FileDitch transfer runner for the provider-authorized ZIP storage workflow."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen
from urllib.error import HTTPError

HOSTS = {"fileditchfiles.st", "fileditchfiles.me"}
ENDPOINT = "https://new.fileditch.com/upload.php"

def checked_url(raw, file_host=False):
    p = urlsplit(str(raw or ""))
    if p.scheme != "https" or not p.hostname or p.username or p.password:
        raise ValueError("HTTPS URL required")
    if file_host and (p.hostname not in HOSTS or p.port is not None):
        raise ValueError("Unexpected FileDitch host")
    return p.geturl()

def safe_name(raw):
    name = re.split(r"[/\\]", str(raw or ""))[-1].strip()
    name = re.sub(r'[<>:"|?*\x00-\x1f]', "_", name)
    if not name or name.startswith(".") or len(name.encode("utf-8")) > 220:
        raise ValueError("Invalid file name")
    return name

def callback(url, body, optional=False):
    """Callback with safe, useful 4xx diagnostics (never print callback tokens)."""
    if not url:
        if optional:
            return
        raise ValueError("Missing callback")
    checked_url(url)
    payload = json.dumps(body).encode("utf-8")
    for attempt in range(5):
        try:
            req = Request(
                url, data=payload, method="POST",
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "User-Agent": "iKiraPlus-FileDitch-Runner/1.1",
                },
            )
            with urlopen(req, timeout=35) as r:
                if not (200 <= r.status < 300):
                    raise RuntimeError(f"Worker callback returned HTTP {r.status}")
                return
        except HTTPError as e:
            raw = e.read(1600).decode("utf-8", errors="replace")
            ctype = (e.headers.get("Content-Type") or "").lower()
            reason = "unknown rejection"
            if "json" in ctype or raw.lstrip().startswith("{"):
                try:
                    code = str(json.loads(raw).get("error") or "")
                    reason = {
                        "invalid token": "callback token mismatch in Worker KV",
                        "not found": "DL link missing in Worker KV",
                        "unauthorized": "callback requires authorization",
                        "missing callback fields": "missing callback request fields",
                    }.get(code, "worker JSON error (review Worker logs)")
                except (ValueError, TypeError):
                    reason = "invalid JSON from Worker"
            elif "<html" in raw.lower() or "text/html" in ctype:
                reason = "HTML denial (check Cloudflare protection / Access)"
            elif e.code == 403:
                reason = "non-JSON 403 (check Cloudflare protection)"
            if e.code in (400, 401, 403, 404, 409):
                if optional:
                    print(f"Failure callback HTTP {e.code}: {reason}", flush=True)
                    return
                raise RuntimeError(f"Worker callback HTTP {e.code}: {reason}") from None
            if attempt == 4:
                if optional:
                    return
                raise RuntimeError(f"Worker callback HTTP {e.code}: {reason}") from None
        except Exception:
            if attempt == 4:
                if optional:
                    return
                raise
        time.sleep(min(2 ** attempt, 12))

def fetch_file(urls, destination, expected):
    for index, url in enumerate(dict.fromkeys(filter(None, urls))):
        checked_url(url)
        try:
            if index and destination.exists(): destination.unlink()
            print(f"Downloading source route {index + 1}", flush=True)
            cmd = ["curl", "-fL", "--silent", "--show-error", "--retry", "5",
                   "--retry-delay", "3", "--retry-all-errors",
                   "--connect-timeout", "35", "--speed-time", "180",
                   "--speed-limit", "1024", "--continue-at", "-",
                   "--output", str(destination), url]
            result = subprocess.run(cmd, timeout=5400, check=False)
            if result.returncode:
                if destination.exists(): destination.unlink()
                cmd.remove("--continue-at")
                cmd.remove("-")
                subprocess.run(cmd, timeout=5400, check=True)
            size = destination.stat().st_size
            if not size or (expected and size != expected):
                raise RuntimeError("Downloaded size mismatch")
            with destination.open("rb") as f:
                if f.read(4) not in (b"PK\x03\x04", b"PK\x05\x06"):
                    raise RuntimeError("IPA lacks ZIP header")
            return size
        except Exception as e:
            print("Download route failed:", type(e).__name__, flush=True)
            if index == len(list(dict.fromkeys(filter(None, urls)))) - 1:
                raise
    raise RuntimeError("No usable download route")

def upload(destination, storage_name, size):
    url = ENDPOINT + "?filename=" + quote(storage_name, safe="")
    for attempt in range(4):
        with tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8") as out:
            p = subprocess.run(
                ["curl", "-sS", "--connect-timeout", "35", "--max-time", "6400",
                 "--request", "PUT", "--upload-file", str(destination),
                 "--output", out.name, "--write-out", "%{http_code}", url],
                capture_output=True, text=True, timeout=6600)
            out.seek(0)
            raw = out.read(10000)
        status = int(p.stdout[-3:]) if p.stdout[-3:].isdigit() else 0
        if status in (200, 201) and p.returncode == 0:
            info = json.loads(raw)
            if info.get("success") is not True or int(info.get("size") or 0) != size:
                raise RuntimeError("Upload size/response mismatch")
            remote = checked_url(info.get("url"), file_host=True)
            saved_name = str(info.get("filename") or "")
            if not saved_name.lower().endswith(".zip"):
                raise RuntimeError("Unexpected stored extension")
            return remote, saved_name
        if status in (400, 403, 413):
            raise RuntimeError(f"FileDitch rejected upload: HTTP {status}")
        if status in (0, 429, 500, 503, 507) and attempt < 3:
            time.sleep((attempt + 1) * 8)
            continue
        raise RuntimeError(f"FileDitch upload HTTP {status or 'network'}")
    raise RuntimeError("Upload retries exhausted")

def verify(remote, size):
    u = urlsplit(checked_url(remote, file_host=True))
    status_url = u.scheme + "://" + u.netloc + "/api" + u.path
    for attempt in range(8):
        try:
            with urlopen(Request(status_url, headers={"Accept":"application/json"}), timeout=30) as r:
                item = json.load(r)
                if item.get("status") is True and int(item.get("size") or 0) == size:
                    return
        except Exception:
            pass
        time.sleep(3 * (attempt + 1))
    raise RuntimeError("Status API could not confirm file size")

def main():
    # Do not put dispatch credentials into an Actions step env value:
    # GitHub prints step environment values before the script can mask them.
    event_path = os.environ["GITHUB_EVENT_PATH"]
    with open(event_path, encoding="utf-8") as f:
        data = (json.load(f).get("client_payload") or {})
    short_id = str(data.get("shortId") or "")
    token = str(data.get("token") or "")
    filename = safe_name(data.get("assetName"))
    expected = int(data.get("expectedSize") or 0)
    if not short_id or not token or not data.get("callbackComplete"):
        raise RuntimeError("Missing task fields")
    for k in ("token", "sourceUrl", "originalUrl", "callbackStarted",
              "callbackComplete", "callbackFailed"):
        v = data.get(k)
        if v: print("::add-mask::" + str(v), flush=True)
    run_id = int(os.environ.get("GITHUB_RUN_ID") or "0")
    run_url = f"https://github.com/{os.environ.get('GITHUB_REPOSITORY', 'ikiraplus/ipa')}/actions/runs/{run_id}"
    base = {"id":short_id, "token":token, "runId":run_id, "runUrl":run_url}
    try:
        callback(data.get("callbackStarted"), base)
        with tempfile.TemporaryDirectory(prefix="fileditch-") as td:
            dest = Path(td) / "source.ipa"
            size = fetch_file([data.get("originalUrl"), data.get("sourceUrl")], dest, expected)
            h = hashlib.sha256()
            with dest.open("rb") as f:
                for chunk in iter(lambda: f.read(4 * 1024 * 1024), b""):
                    h.update(chunk)
            storage_name = filename[:-4] + ".zip" if filename.lower().endswith(".ipa") else filename + ".zip"
            print("Storing authorized ZIP archive without modifying its bytes", flush=True)
            remote, confirmed_name = upload(dest, storage_name, size)
            verify(remote, size)
            callback(data["callbackComplete"], {**base, "url":remote, "size":size,
                "storedName":confirmed_name, "sha256":h.hexdigest()})
            print("Verified upload; DL callback accepted", flush=True)
    except Exception as e:
        print("Transfer failed:", str(e)[:300], flush=True)
        callback(data.get("callbackFailed"), {**base, "message":str(e)[:300]}, optional=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
