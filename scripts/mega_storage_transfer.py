#!/usr/bin/env python3
"""Public runner: URL -> local IPA -> MEGA (rclone) -> DL callback.
Never print credentials or MEGA public keys in the public workflow logs.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from urllib.error import HTTPError

def callback(url, payload, *, optional=False):
    if not url:
        if optional: return
        raise RuntimeError("Missing callback endpoint")
    urlp = urlsplit(url)
    if urlp.scheme != "https" or urlp.hostname != "dl.ikiraplus.workers.dev":
        raise RuntimeError("Untrusted callback endpoint")
    data=json.dumps(payload).encode("utf-8")
    for attempt in range(3):
        try:
            with urlopen(Request(url, data=data, method="POST",
                      headers={"Content-Type":"application/json",
                               "User-Agent":"iKiraPlus-MEGA-Runner/1"}), timeout=30) as res:
                if 200 <= res.status < 300: return
                raise RuntimeError(f"Callback HTTP {res.status}")
        except HTTPError as e:
            if optional: return
            if e.code in (400,401,403,404,409):
                try:
                    detail=json.loads(e.read(300).decode()).get("error","rejected")
                except Exception:
                    detail="rejected"
                raise RuntimeError(f"DL callback HTTP {e.code}: {str(detail)[:65]}") from None
            if attempt==2: raise
        except Exception:
            if attempt==2:
                if optional:return
                raise
        time.sleep(2+attempt*3)

def progress(data, base, stage, done, total, speed=0):
    if total:
        print(f"PROGRESS {stage}: {done/(1024**2):.1f}/{total/(1024**2):.1f} MiB "
              f"({min(99 if stage=='uploading' else 100,100*done/total):.1f}%) "
              f"{speed/(1024**2):.2f}MiB/s",flush=True)
    callback(data.get("callbackProgress"),{**base,"stage":stage,
             "transferredBytes":max(0,int(done)),
             "totalBytes":max(0,int(total)),
             "speedBps":max(0,int(speed))},optional=True)

def download(source, dst, expected, data, base):
    p=urlsplit(source)
    if p.scheme!="https" or not p.hostname or p.username or p.password:
        raise ValueError("Invalid source URL")
    cmd=["curl","-fL","-sS","--retry","4","--retry-all-errors",
         "--connect-timeout","45","--speed-time","180","--speed-limit","1024",
         "--max-time","6500","-o",str(dst),source]
    proc=subprocess.Popen(cmd,stderr=subprocess.DEVNULL)
    last=0;last_update=time.monotonic()
    progress(data,base,"downloading",0,expected)
    try:
        while proc.poll() is None:
            time.sleep(2)
            now=time.monotonic()
            if now-last_update >= 15:
                done=dst.stat().st_size if dst.exists() else 0
                progress(data,base,"downloading",done,expected,(done-last)/(now-last_update))
                last=done;last_update=now
        if proc.returncode:
            raise RuntimeError(f"Source download failed (curl exit {proc.returncode})")
    finally:
        if proc.poll() is None:proc.kill()
    done=dst.stat().st_size
    if not done or (expected and done!=expected):
        raise RuntimeError("Downloaded IPA does not match expected size")
    with dst.open("rb") as f:
        if f.read(4) not in (b"PK\x03\x04",b"PK\x05\x06"):
            raise RuntimeError("Source is not a ZIP/IPA container")
    progress(data,base,"downloading",done,done)
    return done

def upload(dst, remote, size, data, base):
    # First check credentials before transferring multi-GB files.
    conf=os.environ.copy()
    for var in ("RCLONE_CONFIG_MEGA_USER","RCLONE_CONFIG_MEGA_PASS"):
        if not conf.get(var):
            raise RuntimeError(f"Missing GitHub Secret: {var}")
    conf["RCLONE_CONFIG_MEGA_TYPE"]="mega"
    conf["RCLONE_CONFIG_MEGA_USE_HTTPS"]="true"
    # One less MEGA login; this command authenticates and uploads.
    print("MEGA upload phase: authenticating and sending encrypted data", flush=True)
    proc=subprocess.Popen(["rclone","copyto",str(dst),remote,
                 "--stats","15s","--stats-one-line",
                 "--stats-log-level","NOTICE","--use-json-log",
                 "--retries","4","--low-level-retries","8"],
                 env=conf,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,
                 text=True,bufsize=1)
    last_update=0
    print("MEGA upload started",flush=True)
    progress(data,base,"uploading",0,size)
    try:
        for raw in proc.stderr:
            try:
                entry=str(json.loads(raw).get("msg") or "")
            except (TypeError,ValueError):
                entry=raw
            if "Transferred:" not in entry: continue
            m=re.search(r",\s*(\d+(?:\.\d+)?)\s*%",entry)
            if not m: continue
            pct=min(float(m.group(1)),99.0)
            now=time.monotonic()
            if now-last_update>=14:
                progress(data,base,"uploading",int(size*pct/100),size)
                last_update=now
        proc.wait(timeout=120)
    finally:
        if proc.poll() is None:proc.kill()
    if proc.returncode:
        raise RuntimeError(f"MEGA rclone upload failed (exit {proc.returncode})")
    time.sleep(3) # avoid repeated MEGA authentication rate limits
    stats=subprocess.run(["rclone","lsjson","--stat",remote],env=conf,
                   capture_output=True,text=True,timeout=120,check=True)
    metadata=json.loads(stats.stdout)
    if int(metadata.get("Size") or -1)!=size:
        raise RuntimeError("MEGA remote size differs from downloaded IPA")
    time.sleep(3) # avoid rapid repeated stateless MEGA logins
    link=subprocess.run(["rclone","link",remote],env=conf,
                   capture_output=True,text=True,timeout=120,check=True).stdout.strip().splitlines()[-1]
    p=urlsplit(link)
    if p.scheme!="https" or p.hostname not in ("mega.nz","mega.co.nz") or not re.fullmatch(r"/file/[A-Za-z0-9_-]{8,}",p.path) or not re.fullmatch(r"[A-Za-z0-9_-]{40,60}",p.fragment):
        raise RuntimeError("MEGA did not return a recognized public file link")
    return link

def main():
    with open(os.environ["GITHUB_EVENT_PATH"],encoding="utf-8") as f:
        data=json.load(f).get("client_payload") or {}
    id_=str(data.get("shortId") or "")
    token=str(data.get("token") or "")
    source=str(data.get("originalUrl") or "")
    name=re.sub(r'[^A-Za-z0-9._ -]','_',str(data.get("assetName") or ""))[:180].strip(" .")
    if not id_ or not token or not name or not source:raise ValueError("Missing job fields")
    if not name.lower().endswith(".ipa"):raise ValueError("MEGA job requires IPA filename")
    if not re.fullmatch(r"[A-Za-z0-9._~-]{1,120}",id_):raise ValueError("Invalid DL short ID")
    for label in ("token","sourceUrl","originalUrl","callbackStarted",
                  "callbackComplete","callbackFailed","callbackProgress"):
        if data.get(label):print("::add-mask::"+str(data[label]),flush=True)
    run_id=int(os.environ.get("GITHUB_RUN_ID","0"))
    base={"id":id_,"token":token,"runId":run_id,
          "runUrl":f"https://github.com/{os.environ.get('GITHUB_REPOSITORY','ikiraplus/ipa')}/actions/runs/{run_id}"}
    try:
        callback(data.get("callbackStarted"),base)
        started=time.monotonic()
        expected=int(data.get("expectedSize") or 0)
        # Check login before expensive downloads, not after.
        conf=os.environ.copy()
        for var in ("RCLONE_CONFIG_MEGA_USER","RCLONE_CONFIG_MEGA_PASS"):
            if not conf.get(var):
                raise RuntimeError(f"Missing GitHub Secret: {var}")
        # Avoid an extra stateless MEGA login. rclone's MEGA backend warns
        # that repeated fresh logins can cause temporary account blocking.
        # Credentials are checked for presence here; upload handles login.
        print("PHASE credentials: MEGA Secrets present; login occurs during upload",flush=True)
        with tempfile.TemporaryDirectory(prefix="ikiraplus-mega-") as tmp:
            dest=Path(tmp)/name
            print("PHASE download: fetching IPA source", flush=True)
            download_started=time.monotonic()
            size=download(source,dest,expected,data,base)
            print(f"PHASE download complete in {time.monotonic()-download_started:.1f}s; "
                  f"mean speed {size/max(time.monotonic()-download_started,1)/1024**2:.2f}MiB/s",flush=True)
            digest=hashlib.sha256()
            with dest.open("rb") as fd:
                for block in iter(lambda:fd.read(4*1024*1024),b""):digest.update(block)
            remote=f"mega:iKiraPlus-DL/{id_}/{run_id}/{name}"
            upload_started=time.monotonic()
            print("PHASE upload: sending IPA to MEGA",flush=True)
            link=upload(dest,remote,size,data,base)
            print(f"PHASE upload plus verification completed in {time.monotonic()-upload_started:.1f}s",flush=True)
            progress(data,base,"verifying",size,size)
            callback(data.get("callbackComplete"),{**base,"url":link,
                     "size":size,"sha256":digest.hexdigest()})
            print(f"MEGA object verified, DL callback accepted; total time {time.monotonic()-started:.1f}s",flush=True)
    except Exception as e:
        print("MEGA transfer failed:",type(e).__name__,str(e)[:160],flush=True)
        callback(data.get("callbackFailed"),{**base,"message":str(e)[:200]},optional=True)
        raise SystemExit(1)

if __name__=="__main__":main()
