#!/usr/bin/env python3
"""Hard data-integrity assertions. Run BEFORE any evaluation step.
Exits non-zero (aborting run_evaluation.sh) on ANY failure — no tables are produced."""
import csv
import sys
from collections import Counter

errors = []

def check(cond, msg):
    if cond:
        print(f"  PASS {msg}")
    else:
        print(f"  FAIL {msg}")
        errors.append(msg)

# ---- 1. Ransomware Wild class counts must be exactly 5,141 / 10,281 / 2,000 ----
rows = list(csv.DictReader(open("data/manifests/ransomware_wild.csv")))
c = Counter()
for r in rows:
    if r.get("source") == "benign":
        c["benign"] += 1
    else:
        c["pos" if r["label"] == "1" else "neg"] += 1
print("[1] Ransomware Wild class counts")
check(c["pos"] == 5141, f"target(ransomware)=5141 (got {c['pos']})")
check(c["neg"] == 10281, f"other_malware=10281 (got {c['neg']})")
check(c["benign"] == 2000, f"benign=2000 (got {c['benign']})")
check(len(rows) == 17422, f"total rows=17422 (got {len(rows)})")

# Cryptojacking Wild sanity too
rows_c = list(csv.DictReader(open("data/manifests/cryptojacking_wild.csv")))
cc = Counter()
for r in rows_c:
    if r.get("source") == "benign":
        cc["benign"] += 1
    else:
        cc["pos" if r["label"] == "1" else "neg"] += 1
print("[1b] Cryptojacking Wild class counts")
check(cc["pos"] == 6000 and cc["neg"] == 12000 and cc["benign"] == 2000 and len(rows_c) == 20000,
      f"crypto = 6000/12000/2000 (got {cc['pos']}/{cc['neg']}/{cc['benign']}, n={len(rows_c)})")

# ---- 2. manifest uniqueness + prediction-label agreement ----
for task in ("cryptojacking", "ransomware"):
    # uniqueness on (task, hash)
    mani = {}
    dup = 0
    for r in csv.DictReader(open(f"data/manifests/{task}_wild.csv")):
        h = (r.get("hash") or r["filename"]).removesuffix(".exe").removeprefix("VirusShare_")[:32]
        y = 0 if r.get("source") == "benign" else int(r["label"])
        if h in mani and mani[h] != y:
            dup += 1  # same hash with CONFLICTING labels = hard fail
        mani[h] = y
        mani[h[:16]] = y  # 16-hex id form used by prediction sample_ids
    print(f"[2] {task}: uniqueness")
    check(dup == 0, f"{task}_wild unique hashes (dups={dup})")
    # prediction files must agree with manifest labels 100%
    for fn in ("pe2", "avagent"):
        p = f"results/predictions/{fn}_{task}_wild_predictions.csv"
        mism = absent = n = 0
        for r in csv.DictReader(open(p)):
            n += 1
            sid = r["sample_id"][:32]
            if sid not in mani:
                absent += 1
            elif int(r["label"]) != mani[sid]:
                mism += 1
        print(f"[2] {task}/{fn}: label agreement")
        check(mism == 0, f"{fn}_{task} labels match manifest (mismatches={mism}/{n}, not-in-manifest={absent})")

# ---- 3. gate ----
if errors:
    print(f"\nINTEGRITY CHECK FAILED: {len(errors)} error(s). Evaluation aborted; no tables generated.")
    sys.exit(1)
print("\nALL INTEGRITY CHECKS PASSED.")
