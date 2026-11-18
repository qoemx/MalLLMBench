#!/usr/bin/env python3
"""全局规范化: 7个源统一 MZ+PE 双校验 -> sha256 命名 -> 去重 -> 按上游软件族统计 -> 最终manifest"""
import os, re, hashlib, csv, json

BENIGN = "/data/shared-nvme/benign_pe"
FINAL = os.path.join(BENIGN, "final")
os.makedirs(FINAL, exist_ok=True)

SOURCES = [
    ("dike",       os.path.join(BENIGN, "normalized")),     # 已是 md5.exe 命名
    ("msys2",      os.path.join(BENIGN, "raw_msys2")),
    ("conda",      os.path.join(BENIGN, "raw_conda")),
    ("cygwin",     os.path.join(BENIGN, "raw_cygwin")),
    ("virtualbox", os.path.join(BENIGN, "raw_virtualbox")),
    ("python",     os.path.join(BENIGN, "raw_python")),
    ("mozilla",    os.path.join(BENIGN, "raw_mozilla")),
    ("clang64",    os.path.join(BENIGN, "raw_clang64")),
    ("thcrull",    os.path.join(BENIGN, "raw_thcrull_exe")),
]

def check_pe(data):
    if data[:2] != b"MZ": return False
    off = int.from_bytes(data[0x3C:0x40], "little")
    if off + 4 > len(data) or off <= 0: return False
    return data[off:off+4] == b"PE\x00\x00"

# 软件族归一: 从来源信息提取上游项目名
def family_of(source, fn, meta):
    if source == "msys2":
        m = re.match(r"mingw-w64-ucrt-x86_64-(.+?)-\d", meta.get("pkg", ""))
        return m.group(1) if m else fn
    if source == "conda":
        return meta.get("pkg", fn)
    if source == "cygwin":
        p = meta.get("pkg", "").replace("-debuginfo", "").replace("-src", "")
        m = re.match(r"(.+?)-[\d]", p)
        return m.group(1) if m else p
    if source == "python":
        return "python"
    if source == "virtualbox":
        return "virtualbox"
    if source == "mozilla":
        return fn.split("-")[0]
    if source == "clang64":
        m = re.match(r"mingw-w64-clang-x86_64-(.+?)-\d", meta.get("pkg", ""))
        return m.group(1) if m else fn
    if source == "thcrull":
        return meta.get("pkg", fn).replace("Portable", "").replace(".zip", "")
    if source == "dike":
        return "dike-misc"
    return source

# 读各源 manifest (msys2/conda/cygwin 有 jsonl)
metas = {}
for mf, key in [("msys2_manifest.jsonl", "msys2"), ("conda_manifest.jsonl", "conda"), ("cygwin_manifest.jsonl", "cygwin"), ("clang64_manifest.jsonl", "clang64"), ("thcrull_manifest.jsonl", "thcrull")]:
    p = os.path.join(BENIGN, mf)
    if os.path.exists(p):
        for line in open(p):
            try:
                j = json.loads(line)
                metas[(key, j["sha256"] + ".exe")] = j
            except Exception: pass

rows = []
seen_sha = set()
dup = invalid = 0
for source, d in SOURCES:
    if not os.path.isdir(d): continue
    for fn in os.listdir(d):
        p = os.path.join(d, fn)
        if not os.path.isfile(p): continue
        try:
            data = open(p, "rb").read()
        except Exception:
            continue
        if not check_pe(data):
            invalid += 1; continue
        sha = hashlib.sha256(data).hexdigest()
        if sha in seen_sha:
            dup += 1; continue
        seen_sha.add(sha)
        dst = os.path.join(FINAL, sha + ".exe")
        if not os.path.exists(dst):
            os.link(p, dst)
        meta = metas.get((source, fn), {})
        fam = family_of(source, fn, meta)
        rows.append({"sha256": sha, "source": source, "family": fam,
                     "filename": fn, "size": len(data)})

# 统计
from collections import Counter
src_ct = Counter(r["source"] for r in rows)
fam_ct = Counter(r["family"] for r in rows)
print(f"最终唯一 PE: {len(rows)}  (跨源重复 {dup}, 非PE/损坏 {invalid})")
print("\n按来源:")
for s, c in src_ct.most_common():
    print(f"  {s:12s} {c:5d}")
print(f"\n软件族总数: {len(fam_ct)}")
print("Top15 族:")
for f, c in fam_ct.most_common(15):
    print(f"  {f:24s} {c:5d} ({c/len(rows)*100:.1f}%)")

# 写 manifest
with open(os.path.join(BENIGN, "final_manifest.csv"), "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=["sha256", "source", "family", "filename", "size"])
    w.writeheader(); w.writerows(rows)
print(f"\n已写入: {BENIGN}/final_manifest.csv")
print(f"最终目录: {FINAL}")
