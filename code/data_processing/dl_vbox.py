#!/usr/bin/env python3
"""采集 VirtualBox 全部历史版本 Win 安装器 exe (222版本)"""
import os, time, re, urllib.request
import concurrent.futures as cf

OUT = "/data/shared-nvme/benign_pe/raw_virtualbox"
os.makedirs(OUT, exist_ok=True)
UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) research-downloader"}
BASE = "https://download.virtualbox.org/virtualbox/"

def get(url, timeout=180, tries=3):
    for t in range(tries):
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except Exception:
            time.sleep(3)
    return None

idx = get(BASE)
vers = [v.decode() for v in re.findall(rb'href="([0-9][0-9.]+)/"', idx or b"")]
print(f"版本: {len(vers)}", flush=True)

exe_urls = []
for v in vers:
    page = get(f"{BASE}{v}/", timeout=60)
    if not page: continue
    for m in re.findall(rb'href="([^"]*-Win\.exe)"', page):
        exe_urls.append((f"{BASE}{v}/{m.decode()}", m.decode()))
print(f"exe 链接: {len(exe_urls)}", flush=True)

def fetch(item):
    url, fn = item
    dst = os.path.join(OUT, fn)
    if os.path.exists(dst) and os.path.getsize(dst) > 100000:
        return "skip"
    data = get(url, timeout=600)
    if data and data[:2] == b"MZ":
        open(dst, "wb").write(data)
        return "ok"
    return "fail"

ok = fail = 0
with cf.ThreadPoolExecutor(max_workers=4) as ex:
    for i, st in enumerate(ex.map(fetch, exe_urls)):
        ok += st == "ok"; fail += st == "fail"
        if (i + 1) % 20 == 0: print(f"[{i+1}/{len(exe_urls)}] ok={ok} fail={fail}", flush=True)
print(f"DONE ok={ok} fail={fail}", flush=True)
