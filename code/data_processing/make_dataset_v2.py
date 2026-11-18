#!/usr/bin/env python3
"""dataset_v2 划分: 良性 3000(勒索)+3000(挖矿) 并入两任务 Lab/Wild
方案(已确认): 每任务 Lab 1000 + Wild 2000, seed=42, 不重叠, label=0"""
import os
import pandas as pd

BENIGN = "./benign_workspace"
ROOT = "./benign_workspace"
OUT = os.path.join(ROOT, "dataset_v2")
os.makedirs(OUT, exist_ok=True)
SEED = 42

# 1. 良性池: final_manifest.csv -> sha256 列表
man = pd.read_csv(os.path.join(BENIGN, "final_manifest.csv"))
pool = man["sha256"].drop_duplicates().tolist()
print(f"良性池: {len(pool)}")

# 2. 随机分两批 3000 + 3000 (剩余 1000 备用)
rng = pd.Series(pool).sample(frac=1, random_state=SEED).tolist()
ransom_benign = rng[:3000]
crypto_benign = rng[3000:6000]
reserve = rng[6000:]
assert not (set(ransom_benign) & set(crypto_benign))
print(f"勒索: {len(ransom_benign)}, 挖矿: {len(crypto_benign)}, 备用: {len(reserve)}")

# 3. 每任务内部 Lab 1000 / Wild 2000
def split_lab_wild(shas):
    s = pd.Series(shas).sample(frac=1, random_state=SEED).tolist()
    return s[:1000], s[1000:3000]

r_lab, r_wild = split_lab_wild(ransom_benign)
c_lab, c_wild = split_lab_wild(crypto_benign)

# 4. 组装 CSV: 恶意部分照抄原文件, 良性行追加 (filename=sha256.exe, label=0, source=benign)
def build(ransom: bool, split: str, benign_shas):
    if ransom:
        src = os.path.join(ROOT, "balanced_lab_dataset_1to2.csv") if split == "lab" \
              else os.path.join(ROOT, "balanced_wild_dataset_1to2.csv")
    else:
        src = os.path.join(ROOT, "Crypto_experient", "lab_label.csv") if split == "lab" \
              else os.path.join(ROOT, "Crypto_experient", "wild_label.csv")
    df = pd.read_csv(src)
    orig_cols = list(df.columns)
    # 统一输出列: filename,hash,label,source,file_path
    out = df.rename(columns={"first_submission": "first_submission_date"}) if not ransom else df.copy()
    out["source"] = "malware_virusshare"
    out["file_path"] = out["file_path"] if "file_path" in out.columns else ""
    benign_rows = []
    for sha in benign_shas:
        benign_rows.append({
            "filename": sha + ".exe", "hash": sha, "label": 0, "source": "benign",
            "file_path": os.path.join(BENIGN, "final", sha + ".exe"),
        })
    bdf = pd.DataFrame(benign_rows)
    keep = [c for c in ["filename", "hash", "label", "source", "file_path"] if True]
    out2 = out[[c for c in keep if c in out.columns]]
    bdf2 = bdf[keep]
    merged = pd.concat([out2, bdf2], ignore_index=True)
    task = "ransomware" if ransom else "cryptojacking"
    dst = os.path.join(OUT, f"{task}_{split}_v2.csv")
    merged.to_csv(dst, index=False)
    # 统计
    n_pos = (merged["label"] == 1).sum(); n_mal0 = ((merged["label"] == 0) & (merged["source"] != "benign")).sum()
    n_ben = (merged["source"] == "benign").sum()
    print(f"{dst.split('/')[-1]:28s} 总{len(merged):>6} 正{n_pos:>5} 恶意负{n_mal0:>6} 良性{n_ben:>5} 正:负=1:{(n_mal0+n_ben)/n_pos:.2f}")

build(True,  "lab",  r_lab)
build(True,  "wild", r_wild)
build(False, "lab",  c_lab)
build(False, "wild", c_wild)

# 5. 备用清单
pd.DataFrame({"sha256": reserve}).to_csv(os.path.join(OUT, "benign_reserve_1000.csv"), index=False)
print("\n完成 → dataset_v2/")
