#!/usr/bin/env python3
"""Cygwin 良性 PE 采集器 (清华镜像): setup.xz 索引 -> 筛包 -> curl下载(限频) -> 提取exe"""
import os, re, time, json, hashlib, subprocess, urllib.parse, tarfile

BENIGN = "/data/shared-nvme/benign_pe"
PKGDIR = os.path.join(BENIGN, "cygwin_pkgs")
OUT = os.path.join(BENIGN, "raw_cygwin")
for d in (PKGDIR, OUT):
    os.makedirs(d, exist_ok=True)
BASE = "https://mirrors.tuna.tsinghua.edu.cn/cygwin/x86_64"
TARGET = 800
CAP = 3
EXCLUDE = re.compile(r"^(cygwin$|lib|_autorebase|_update-info-dir|bash|coreutils|grep|sed|gawk|findutils|tar$|gzip|bzip2|xz$|zlib|openssl|perl|python|ruby|gcc|gmp|mpfr|mpc|binutils|make$|mingw)", re.I)

# 1. 下载解压 setup.ini
ini_path = os.path.join(BENIGN, "cygwin_setup.ini")
if not os.path.exists(ini_path):
    subprocess.run(["bash", "-c",
        f"curl -sL --max-time 120 {BASE}/setup.xz | xz -dc > {ini_path}"], check=True)
txt = open(ini_path, encoding="utf-8", errors="ignore").read()
print(f"setup.ini: {len(txt)} 字符", flush=True)

# 2. 解析 install 行
pkgs = []
for m in re.finditer(r"^@ (\S+)\n(?:[^\n]*\n)*?install: (\S+) (\S+)", txt, re.M):
    name, path, size = m.group(1), m.group(2), int(m.group(3))
    if EXCLUDE.search(name): continue
    if size > 60_000_000 or size < 30_000: continue
    path = path.lstrip("/")
    if path.startswith("x86_64/"):
        path = path[len("x86_64/"):]
    pkgs.append((name, path, size))
print(f"计划包: {len(pkgs)}", flush=True)

manifest = os.path.join(BENIGN, "cygwin_manifest.jsonl")
done = set()
if os.path.exists(manifest):
    for line in open(manifest):
        try: done.add(json.loads(line)["sha256"])
        except Exception: pass

def process(name, relpath):
    local = os.path.join(PKGDIR, os.path.basename(relpath))
    try:
        ok = False
        for _ in range(3):
            subprocess.run(["curl", "-s", "--max-time", "180", "-o", local,
                            f"{BASE}/{urllib.parse.quote(relpath)}"], timeout=240)
            if os.path.exists(local) and os.path.getsize(local) > 1000:
                with open(local, "rb") as f:
                    magic = f.read(3)
                    if magic[:2] == b"\xfd7" or magic[:2] == b"BZ":  # xz or bz2
                        ok = True; break
                os.remove(local)
            time.sleep(5)
        if not ok: return []
        out = []
        dec = subprocess.Popen(["xz", "-dc", local], stdout=subprocess.PIPE)
        with tarfile.open(fileobj=dec.stdout, mode="r|") as tf:
            taken = 0
            for member in tf:
                if taken >= CAP: break
                n = member.name
                if not (member.isfile() and n.endswith(".exe")): continue
                d = tf.extractfile(member).read()
                if len(d) > 60e6 or d[:2] != b"MZ": continue
                off = int.from_bytes(d[0x3C:0x40], "little")
                if off+4 > len(d) or d[off:off+4] != b"PE\x00\x00": continue
                sha = hashlib.sha256(d).hexdigest()
                dst = os.path.join(OUT, sha + ".exe")
                if not os.path.exists(dst):
                    open(dst, "wb").write(d)
                out.append({"sha256": sha, "pkg": name, "inner": n, "size": len(d)})
                taken += 1
        dec.stdout.close(); dec.wait()
        os.remove(local)
        return out
    except Exception:
        if os.path.exists(local):
            try: os.remove(local)
            except Exception: pass
        return []

mf = open(manifest, "a")
count = len(done)
t0 = time.time()
for i, (name, relpath, size) in enumerate(pkgs):
    if count >= TARGET: break
    got = process(name, relpath)
    for g in got:
        if g["sha256"] not in done:
            done.add(g["sha256"])
            mf.write(json.dumps(g, ensure_ascii=False) + "\n"); mf.flush()
            count += 1
    if (i+1) % 30 == 0:
        print(f"[{i+1}/{len(pkgs)}] 累计 {count} ({time.time()-t0:.0f}s)", flush=True)
    time.sleep(5.5)
mf.close()
print(f"DONE {count}", flush=True)
