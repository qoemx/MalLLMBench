#!/usr/bin/env python3
"""conda-forge win-64 良性 PE 采集器 (清华镜像)
repodata 选包 -> curl 下载 .conda/.tar.bz2 -> 解包提取 Library/bin 的 PE exe"""
import os, re, json, time, hashlib, subprocess, urllib.parse
import concurrent.futures as cf

BENIGN = "./benign_workspace"
PKGDIR = os.path.join(BENIGN, "conda_pkgs")
OUT = os.path.join(BENIGN, "raw_conda")
for d in (PKGDIR, OUT):
    os.makedirs(d, exist_ok=True)
BASE = "https://mirrors.tuna.tsinghua.edu.cn/anaconda/cloud/conda-forge/win-64"
TARGET = 1500
MAX_PKG_MB = 80
CAP_PER_PKG = 3
# 排除纯 python 启动器类包和超基础库
EXCLUDE = re.compile(r"^(python|pip|setuptools|wheel|conda|conda-|certifi|idna|urllib3|requests$|six|packaging)", re.I)
PREFER = re.compile(r"(ffmpeg|imagemagick|cmake|ninja|gdal|qgis|graphviz|poppler|ghostscript|libreoffice|blender|meshlab|pcl|opencv|vlc|mpv|7zip|p7zip|curl|wget|git|mercurial|svn|nodejs|deno|rust|gcc|clang|llvm|go[-_]|java|openjdk|jdk|maven|gradle|ant|nginx|apache|redis|memcached|postgresql|mysql|sqlite|mosquitto|rabbitmq|zookeeper|kafka|hadoop|spark|julia|r-base|perl|ruby|php|lua|tcl|tk|qt5|qt6|gtk|wxwidgets|sdl|sfml|godot|assimp|ffmpeg|gstreamer|boost|eigen|armadillo|numpy|scipy|pandas$)", re.I)

manifest = os.path.join(BENIGN, "conda_manifest.jsonl")
done = set()
if os.path.exists(manifest):
    for line in open(manifest):
        try: done.add(json.loads(line)["sha256"])
        except Exception: pass
print(f"已有 {len(done)}", flush=True)

# ---- 下载 repodata ----
repo_path = os.path.join(BENIGN, "conda_repodata.json")
if not os.path.exists(repo_path):
    subprocess.run(["curl", "-sL", "--max-time", "600", "--retry", "3",
                    "-A", "Mozilla/5.0", "-o", repo_path,
                    f"{BASE}/current_repodata.json"], check=True)
data = json.load(open(repo_path))
pkgs = {}
pkgs.update(data.get("packages", {}))
pkgs.update(data.get("packages.conda", {}))
print(f"repodata 包总数: {len(pkgs)}", flush=True)

# 选包: 优先功能型软件, 排除启动器类; 每个项目名只取最新1个版本
by_name = {}
for fname, p in pkgs.items():
    name = p.get("name", "")
    if EXCLUDE.search(name): continue
    if p.get("size", 0) > MAX_PKG_MB * 1e6 or p.get("size", 0) < 200_000: continue
    prev = by_name.get(name)
    if prev is None or PREFER.search(name) and not PREFER.search(prev[1].get("name","")):
        by_name[name] = (fname, p)
    # 同名取版本号新的略复杂, 简化: 保留首个
plan = list(by_name.values())
print(f"去重后计划包数: {len(plan)}", flush=True)

def process(fname, meta):
    local = os.path.join(PKGDIR, fname)
    try:
        for _ in range(3):
            r = subprocess.run(["curl", "-sL", "--max-time", "240", "--retry", "2",
                                "-A", "Mozilla/5.0", "-o", local + ".tmp",
                                f"{BASE}/{urllib.parse.quote(fname)}"], timeout=300)
            if r.returncode == 0 and os.path.exists(local + ".tmp") and os.path.getsize(local + ".tmp") > 1000:
                os.replace(local + ".tmp", local); break
        else:
            return []
        out = []
        # .conda = zst 压缩的 tar; .tar.bz2 也可能
        if fname.endswith(".conda"):
            proc = subprocess.Popen(["zstd", "-dc", local], stdout=subprocess.PIPE)
            mode = "r|"
        else:
            proc = None
        import tarfile
        if proc:
            tf = tarfile.open(fileobj=proc.stdout, mode="r|")
        else:
            tf = tarfile.open(local, "r:bz2")
        with tf:
            taken = 0
            for member in tf:
                if taken >= CAP_PER_PKG: break
                n = member.name
                if member.isfile() and n.endswith(".exe") and ("/bin/" in n or "/Scripts/" not in n):
                    if "Scripts/" in n: continue  # 排除python启动器
                    data_bytes = tf.extractfile(member).read()
                    if len(data_bytes) > 60e6 or data_bytes[:2] != b"MZ": continue
                    off = int.from_bytes(data_bytes[0x3C:0x40], "little")
                    if off+4 > len(data_bytes) or data_bytes[off:off+4] != b"PE\x00\x00": continue
                    sha = hashlib.sha256(data_bytes).hexdigest()
                    dst = os.path.join(OUT, sha + ".exe")
                    if not os.path.exists(dst):
                        open(dst, "wb").write(data_bytes)
                    out.append({"sha256": sha, "pkg": meta.get("name"), "ver": meta.get("version"),
                                "inner": n, "size": len(data_bytes)})
                    taken += 1
        if proc:
            proc.stdout.close(); proc.wait()
        os.remove(local)
        return out
    except Exception:
        if os.path.exists(local):
            try: os.remove(local)
            except Exception: pass
        return []

mf = open(manifest, "a")
count = len(done)
lock = __import__("threading").Lock()

def run(item):
    global count
    with lock:
        if count >= TARGET: return 0
    fname, meta = item
    got = process(fname, meta)
    with lock:
        for g in got:
            if g["sha256"] not in done:
                done.add(g["sha256"])
                mf.write(json.dumps(g, ensure_ascii=False) + "\n"); mf.flush()
                count += 1
    return len(got)

with cf.ThreadPoolExecutor(max_workers=6) as ex:
    for i, n in enumerate(ex.map(run, plan)):
        if (i + 1) % 50 == 0:
            print(f"[{i+1}/{len(plan)}] 累计: {count}", flush=True)
        if count >= TARGET:
            print("达目标", flush=True); break
mf.close()
print(f"DONE 累计: {count}", flush=True)
