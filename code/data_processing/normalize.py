#!/usr/bin/env python3
"""规范化已下载的良性 PE: 校验MZ头 -> 按MD5统一命名 -> 生成清单CSV"""
import os, hashlib, csv

BENIGN = "./benign_workspace"
OUT = os.path.join(BENIGN, "normalized")
os.makedirs(OUT, exist_ok=True)

def md5(p, _cache={}):
    if p in _cache: return _cache[p]
    h = hashlib.md5()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    _cache[p] = h.hexdigest()
    return _cache[p]

rows = []
seen_md5 = set()
dup = inv = 0

# 源1: DikeDataset (sha256命名)
for fn in sorted(os.listdir(os.path.join(BENIGN, "raw_dike"))):
    p = os.path.join(BENIGN, "raw_dike", fn)
    with open(p, "rb") as f:
        if f.read(2) != b"MZ":
            inv += 1; continue
    m = md5(p)
    if m in seen_md5:
        dup += 1; continue
    seen_md5.add(m)
    dst = os.path.join(OUT, f"{m}.exe")
    if not os.path.exists(dst):
        os.link(p, dst)
    rows.append([f"{m}.exe", "dike", fn, os.path.getsize(p)])

# 源2: Sysinternals
for fn in sorted(os.listdir(os.path.join(BENIGN, "sysi_extract"))):
    if not fn.lower().endswith(".exe"): continue
    p = os.path.join(BENIGN, "sysi_extract", fn)
    with open(p, "rb") as f:
        if f.read(2) != b"MZ":
            inv += 1; continue
    m = md5(p)
    if m in seen_md5:
        dup += 1; continue
    seen_md5.add(m)
    dst = os.path.join(OUT, f"{m}.exe")
    if not os.path.exists(dst):
        os.link(p, dst)
    rows.append([f"{m}.exe", "sysinternals", fn, os.path.getsize(p)])

with open(os.path.join(BENIGN, "manifest.csv"), "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["filename", "source", "original_name", "size_bytes"])
    w.writerows(rows)

print(f"规范化完成: {len(rows)} 个唯一良性PE (重复{dup}, 非PE{inv})")
print(f"输出目录: {OUT}")
print(f"清单: {os.path.join(BENIGN, 'manifest.csv')}")
