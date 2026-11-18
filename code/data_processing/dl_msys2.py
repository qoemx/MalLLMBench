#!/usr/bin/env python3
"""MSYS2 UCRT64 良性 PE 采集器 v2 — 用 zstd -dc 管流式读 tar"""
import os, re, json, time, hashlib, tarfile, subprocess, urllib.request, urllib.parse
import concurrent.futures as cf

BENIGN = "./benign_workspace"
IDX = os.path.join(BENIGN, "msys2_idx")
PKGDIR = os.path.join(BENIGN, "msys2_pkgs")
OUT = os.path.join(BENIGN, "raw_msys2")
for d in (PKGDIR, OUT):
    os.makedirs(d, exist_ok=True)
UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) research-downloader"}
BASE = "https://mirrors.tuna.tsinghua.edu.cn/msys2/mingw/ucrt64"
CAP_PER_PKG = 3
MAX_PKG_MB = 120
MAX_EXE_MB = 60
TARGET = 3200

plan = []
for pkg in sorted(os.listdir(IDX)):
    fdesc = os.path.join(IDX, pkg, "desc")
    ffiles = os.path.join(IDX, pkg, "files")
    if not (os.path.exists(fdesc) and os.path.exists(ffiles)): continue
    desc = open(fdesc, encoding="utf-8", errors="ignore").read()
    m = re.search(r"%FILENAME%\n(.*?)\n", desc)
    if not m: continue
    fname = m.group(1)
    if not fname.endswith(".pkg.tar.zst"):
        fname += ".pkg.tar.zst"
    ms = re.search(r"%CSHA256SUM%\n(.*?)\n", desc)
    csha = ms.group(1) if ms else None
    msize = re.search(r"%SIZE%\n(.*?)\n", desc)
    size = int(msize.group(1)) if msize else 0
    if size > MAX_PKG_MB * 1e6: continue
    exes = []
    for line in open(ffiles, encoding="utf-8", errors="ignore"):
        line = line.strip()
        if line.endswith(".exe") and "/" in line and not line.startswith("%"):
            exes.append(line)
    if exes:
        plan.append({"pkg": pkg, "fname": fname, "csha": csha, "size": size,
                     "exes": set(e.rsplit("/", 1)[-1] for e in exes[:CAP_PER_PKG * 2])})
print(f"计划包数: {len(plan)}", flush=True)

def process(item):
    pkg, fname, csha = item["pkg"], item["fname"], item["csha"]
    zst = os.path.join(PKGDIR, fname)
    try:
        for attempt in range(3):
            try:
                url = f"{BASE}/{urllib.parse.quote(fname)}"
                r = subprocess.run(
                    ["curl", "-sL", "--max-time", "300", "--retry", "2",
                     "-A", "Mozilla/5.0 (X11; Linux x86_64) research-downloader",
                     "-o", zst + ".tmp", url],
                    timeout=360)
                if r.returncode == 0 and os.path.exists(zst + ".tmp") and os.path.getsize(zst + ".tmp") > 500:
                    os.replace(zst + ".tmp", zst)
                    break
            except Exception:
                pass
            time.sleep(3)
        else:
            return []
        # zstd 管道流式读 tar
        out = []
        proc = subprocess.Popen(["zstd", "-dc", zst], stdout=subprocess.PIPE)
        with tarfile.open(fileobj=proc.stdout, mode="r|") as tf:
            taken = 0
            for member in tf:
                base = member.name.rsplit("/", 1)[-1]
                if member.isfile() and member.name.endswith(".exe") and base in item["exes"] and taken < CAP_PER_PKG:
                    fobj = tf.extractfile(member)
                    data = fobj.read()
                    if len(data) > MAX_EXE_MB * 1e6: continue
                    if data[:2] != b"MZ": continue
                    off = int.from_bytes(data[0x3C:0x40], "little")
                    if off + 4 > len(data) or data[off:off+4] != b"PE\x00\x00": continue
                    sha = hashlib.sha256(data).hexdigest()
                    dst = os.path.join(OUT, sha + ".exe")
                    if not os.path.exists(dst):
                        open(dst, "wb").write(data)
                    out.append({"sha256": sha, "pkg": pkg, "inner": member.name, "size": len(data)})
                    taken += 1
        proc.stdout.close(); proc.wait()
        os.remove(zst)
        return out
    except Exception:
        if os.path.exists(zst):
            try: os.remove(zst)
            except Exception: pass
        return []

manifest = os.path.join(BENIGN, "msys2_manifest.jsonl")
done_shas = set()
if os.path.exists(manifest):
    for line in open(manifest):
        try: done_shas.add(json.loads(line)["sha256"])
        except Exception: pass
print(f"已有 {len(done_shas)} 个", flush=True)
mf = open(manifest, "a")
count = len(done_shas)
lock = __import__("threading").Lock()

def run(item):
    global count
    with lock:
        if count >= TARGET: return 0
    got = process(item)
    with lock:
        for g in got:
            if g["sha256"] not in done_shas:
                done_shas.add(g["sha256"])
                mf.write(json.dumps(g, ensure_ascii=False) + "\n"); mf.flush()
                count += 1
    return len(got)

with cf.ThreadPoolExecutor(max_workers=8) as ex:
    for i, n in enumerate(ex.map(run, plan)):
        if (i + 1) % 50 == 0:
            print(f"[{i+1}/{len(plan)}] 累计唯一exe: {count}", flush=True)
        if count >= TARGET:
            print("达目标", flush=True); break
mf.close()
print(f"DONE 唯一exe: {count}", flush=True)
