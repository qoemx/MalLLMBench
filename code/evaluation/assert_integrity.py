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

# ---- 1. ALL FOUR partitions: exact class counts + benign labels forced 0 ----
EXPECT = {
    "cryptojacking_lab":   (2000, 3999, 1000, 6999),
    "cryptojacking_wild":  (6000, 12000, 2000, 20000),
    "ransomware_lab":      (2000, 4000, 1000, 7000),
    "ransomware_wild":     (5141, 10281, 2000, 17422),
}
manifest_cache = {}
for name, (epos, eneg, eben, etot) in EXPECT.items():
    rows = list(csv.DictReader(open(f"data/manifests/{name}.csv")))
    c = Counter()
    ben_labels = set()
    for r in rows:
        if r.get("source") == "benign":
            c["benign"] += 1
            ben_labels.add(r["label"])
        else:
            c["pos" if r["label"] == "1" else "neg"] += 1
    print(f"[1] {name}")
    check(c["pos"] == epos, f"target=1 count {epos} (got {c['pos']})")
    check(c["neg"] == eneg, f"other-malware=0 count {eneg} (got {c['neg']})")
    check(c["benign"] == eben, f"benign count {eben} (got {c['benign']})")
    check(len(rows) == etot, f"total rows {etot} (got {len(rows)})")
    check(ben_labels <= {"0"}, f"benign rows all label=0 (got labels {ben_labels or '{}'})")
    manifest_cache[name] = rows

# ---- 2. hash uniqueness (conflicting labels = fail) + prediction-label agreement ----
mani = {}
for task in ("cryptojacking", "ransomware"):
    m = {}
    dup = 0
    for split in ("wild",):
        for r in manifest_cache[f"{task}_{split}"]:
            h = (r.get("hash") or r["filename"]).removesuffix(".exe").removeprefix("VirusShare_")[:32]
            y = 0 if r.get("source") == "benign" else int(r["label"])
            if h in m and m[h] != y:
                dup += 1
            m[h] = y
            m[h[:16]] = y
    mani[task] = m
    print(f"[2] {task}_wild uniqueness")
    check(dup == 0, f"unique hashes, no conflicting labels (conflicts={dup})")
    for fn in ("pe2", "avagent"):
        p = f"results/predictions/{fn}_{task}_wild_predictions.csv"
        mism = absent = n = 0
        for r in csv.DictReader(open(p)):
            n += 1
            sid = r["sample_id"][:32]
            if sid not in m:
                absent += 1
            elif int(r["label"]) != m[sid]:
                mism += 1
        print(f"[2] {task}/{fn}: label agreement")
        check(mism == 0 and absent == 0, f"{fn}_{task} labels match manifest (mismatches={mism}/{n}, not-in-manifest={absent})")

# ---- 3. Lab manifest usable for training (positive+negative both present) ----
for name in EXPECT:
    if not name.endswith("_lab"):
        continue
    rows = manifest_cache[name]
    pos = sum(1 for r in rows if r.get("source") != "benign" and r["label"] == "1")
    neg = sum(1 for r in rows if r.get("source") != "benign" and r["label"] == "0")
    print(f"[3] {name} trainability")
    check(pos >= 2000 and neg >= 3999, f"lab has both classes (pos={pos}, neg={neg}) — guards the all-ones corruption")

# ---- 4. gate ----
if errors:
    print(f"\nINTEGRITY CHECK FAILED: {len(errors)} error(s). Evaluation aborted; no tables generated.")
    sys.exit(1)
print("\nALL INTEGRITY CHECKS PASSED.")
