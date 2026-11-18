#!/usr/bin/env python3
"""采集 Mozilla Firefox/Thunderbird 历史版本 win64 安装器 (英文+若干语言, 控制在~3000个)"""
import os, time, re, urllib.request, urllib.parse
import concurrent.futures as cf

OUT = "/data/shared-nvme/benign_pe/raw_mozilla"
os.makedirs(OUT, exist_ok=True)
UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) research-downloader"}
LANGS = ["en-US", "en-GB", "de", "fr", "es-ES", "ja", "zh-CN", "zh-TW", "ru", "pt-BR", "it", "ko"]
TARGET = 3000

def get(url, timeout=90, tries=2):
    for t in range(tries):
        try:
            req = urllib.request.Request(urllib.parse.quote(url, safe=":/"), headers=UA)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except Exception:
            time.sleep(2)
    return None

# 收集版本(过滤掉 esr/beta 符号版本目录? 全收)
urls = []
for prod in ["firefox", "thunderbird"]:
    idx = get(f"https://ftp.mozilla.org/pub/{prod}/releases/")
    if not idx: continue
    vers = [v.decode().rstrip("/") for v in re.findall(rb'>([0-9][0-9a-zA-Z.]+)/<', idx)]
    print(f"{prod}: {len(vers)} 版本", flush=True)
    for v in vers:
        for lang in LANGS:
            urls.append((f"https://ftp.mozilla.org/pub/{prod}/releases/{v}/win64/{lang}/"
                         f"{prod.title().replace('Thunderbird','Thunderbird')} Setup {v}.exe"
                         if prod == "thunderbird" else
                         f"https://ftp.mozilla.org/pub/{prod}/releases/{v}/win64/{lang}/Firefox Setup {v}.exe",
                         f"{prod}-{v}-{lang}.exe"))
print(f"候选URL: {len(urls)}", flush=True)

def fetch(item):
    url, fn = item
    dst = os.path.join(OUT, fn)
    if os.path.exists(dst) and os.path.getsize(dst) > 1000000:
        return "skip"
    data = get(url, timeout=300)
    if data and data[:2] == b"MZ":
        open(dst, "wb").write(data)
        return "ok"
    return "fail"

ok = fail = 0
with cf.ThreadPoolExecutor(max_workers=8) as ex:
    for i, st in enumerate(ex.map(fetch, urls)):
        ok += st == "ok"; fail += st == "fail"
        if (i + 1) % 100 == 0:
            print(f"[{i+1}/{len(urls)}] ok={ok} fail={fail}", flush=True)
            if ok >= TARGET:
                print("达到目标,停止", flush=True)
                break
print(f"DONE ok={ok} fail={fail}", flush=True)
