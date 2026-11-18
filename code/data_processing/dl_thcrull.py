#!/usr/bin/env python3
"""下载 Thcrull 数据集 benign_samples (PortableApps/Sysinternals/安装器/.NET) 762个zip, 解包提取exe"""
import os, io, re, time, zipfile, urllib.request, urllib.parse
import concurrent.futures as cf

BENIGN = "/data/shared-nvme/benign_pe"
OUT = os.path.join(BENIGN, "raw_thcrull")
os.makedirs(OUT, exist_ok=True)
UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) research-downloader"}
BASE = "https://hf-mirror.com/api/datasets/Thcrull/win-exe-malware-analysis"
DL = "https://hf-mirror.com/datasets/Thcrull/win-exe-malware-analysis/resolve/main"

def api(url, tries=4):
    for t in range(tries):
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=90) as r:
                return json.load(r)
        except Exception as e:
            time.sleep(4 * (t + 1))
    return None

import json

dirs = ["benign_samples/PortableApps", "benign_samples/PortableAppsInstallers",
        "benign_samples/SysinternalsSuite", "benign_samples/Benign-NET-netwindows"]
files = []
for d in dirs:
    page = 1
    while True:
        items = api(f"{BASE}/tree/main/{d}?limit=1000" + (f"&page={page}" if page > 1 else ""))
        if not items: break
        for it in items:
            if it.get("type") == "file":
                files.append(it["path"])
        if len(items) < 1000: break
        page += 1
    print(f"{d}: 累计 {len(files)}", flush=True)
print(f"总文件: {len(files)}", flush=True)

def fetch(path):
    fn = path.split("/")[-1]
    dst = os.path.join(OUT, fn)
    if os.path.exists(dst) and os.path.getsize(dst) > 0:
        return "skip"
    for t in range(3):
        try:
            req = urllib.request.Request(f"{DL}/{urllib.parse.quote(path)}", headers=UA)
            with urllib.request.urlopen(req, timeout=300) as r:
                data = r.read()
            open(dst, "wb").write(data)
            return "ok"
        except Exception:
            time.sleep(4)
    return "fail"

ok = fail = 0
with cf.ThreadPoolExecutor(max_workers=6) as ex:
    for i, st in enumerate(ex.map(fetch, files)):
        ok += st == "ok"; fail += st == "fail"
        if (i + 1) % 50 == 0: print(f"[{i+1}/{len(files)}] ok={ok} fail={fail}", flush=True)
print(f"ZIP下载完成: ok={ok} fail={fail}", flush=True)
