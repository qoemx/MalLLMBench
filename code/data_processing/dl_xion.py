#!/usr/bin/env python3
"""下载 XION benign 分卷 (part_aa..ad) 到 /data 盘"""
import os, time, sys
import urllib.request

OUT = "./benign_workspace/pkgs"
os.makedirs(OUT, exist_ok=True)
BASE = "https://hf-mirror.com/datasets/AquaCoder0010/XION-Malware-Benign-dataset/resolve/main"
UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) research-downloader"}
PARTS = ["part_aa", "part_ab", "part_ac", "part_ad"]

def fetch(part):
    dst = os.path.join(OUT, part)
    while True:
        have = os.path.getsize(dst) if os.path.exists(dst) else 0
        req = urllib.request.Request(f"{BASE}/{part}", headers={**UA, "Range": f"bytes={have}-"})
        try:
            with urllib.request.urlopen(req, timeout=300) as r, open(dst, "ab") as f:
                total = r.headers.get("Content-Range", "?")
                print(f"[{part}] 从 {have} 续传 (总 {total})", flush=True)
                while True:
                    chunk = r.read(1 << 18)
                    if not chunk: break
                    f.write(chunk)
            print(f"[{part}] 完成 {os.path.getsize(dst)}", flush=True)
            return True
        except Exception as e:
            print(f"[{part}] err {e}, 5s后续传", flush=True)
            time.sleep(5)

for p in PARTS:
    fetch(p)
print("ALL_DONE", flush=True)
