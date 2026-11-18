#!/usr/bin/env python3
"""从 python.org/ftp 采集全部 Windows 安装器 exe (281个版本 × ~3变体)"""
import os, time, re, urllib.request
import concurrent.futures as cf

OUT = "./benign_workspace/raw_python"
os.makedirs(OUT, exist_ok=True)
UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) research-downloader"}

def get(url, tries=3):
    for t in range(tries):
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=120) as r:
                return r.read()
        except Exception:
            time.sleep(3 * (t + 1))
    return None

# 版本列表
idx = get("https://www.python.org/ftp/python/")
versions = re.findall(rb'href="([0-9][0-9a-zA-Z.]+)/"', idx or b"")
versions = [v.decode() for v in versions]
print(f"版本数: {len(versions)}", flush=True)

# 收集所有 exe 链接
tasks = []
for v in versions:
    page = get(f"https://www.python.org/ftp/python/{v}/")
    if not page: continue
    for m in re.findall(rb'href="([^"]+\.exe)"', page):
        fn = m.decode()
        tasks.append((f"https://www.python.org/ftp/python/{v}/{fn}", fn))
print(f"exe 链接总数: {len(tasks)}", flush=True)

def fetch(item):
    url, fn = item
    dst = os.path.join(OUT, fn)
    if os.path.exists(dst) and os.path.getsize(dst) > 1000:
        return "skip"
    data = get(url)
    if data and data[:2] == b"MZ":
        open(dst, "wb").write(data)
        return "ok"
    return "fail"

ok = fail = 0
with cf.ThreadPoolExecutor(max_workers=6) as ex:
    for i, st in enumerate(ex.map(fetch, tasks)):
        ok += st == "ok"; fail += st == "fail"
        if (i+1) % 50 == 0: print(f"[{i+1}/{len(tasks)}] ok={ok} fail={fail}", flush=True)
print(f"完成: ok={ok} fail={fail}", flush=True)
