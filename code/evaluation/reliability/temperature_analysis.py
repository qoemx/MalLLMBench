#!/usr/bin/env python3
"""M1 temperature/stability analysis from shipped three-run records (F1 mean/std + disagreement).
Reads results/reliability/<method>_<task>/ jsonl runs; outputs per-temperature F1 mean/std + disagreement."""
import csv, json, os, glob
import numpy as np

BASE = "results/reliability"
OUT = "results/reliability/summary_temperature.csv"

GROUPS = {
    "pe2_cryptojacking": ("repeat_v2_T{T}_run{r}.jsonl", "prediction", lambda d: 1 if str(d.get("prediction")) == "cryptominer" else 0),
    "pe2_ransomware":    ("repeat_r_T{T}_run{r}.jsonl", "prediction", None),
    "avagent_cryptojacking": ("avagent_p2_temp_T{T}_run{r}.jsonl", None, lambda d: d.get("prediction")),
    "avagent_ransomware":    ("avagent_r_temp_T{T}_run{r}.jsonl", None, lambda d: d.get("final")),
}
# AV crypto T=0 files named avagent_p2_repeat300_run{r}
def files_for(group, T, r):
    pat = GROUPS[group][0]
    if group == "avagent_cryptojacking" and T == 0.0:
        return os.path.join(BASE, group, f"avagent_p2_repeat300_run{r}.jsonl")
    return os.path.join(BASE, group, pat.format(T=T, r=r))

def load(group, T, r, allowed=None):
    fn = files_for(group, T, r)
    conv = GROUPS[group][2]
    out = {}
    for l in open(fn):
        d = json.loads(l)
        if allowed is not None and d["sample_id"] not in allowed:
            continue
        if group.startswith("pe2"):
            p = d.get("prediction")
            v = 1 if p == "cryptominer" or p == "ransomware" or p == 1 else (0 if p in ("non_miner", "non_ransomware", 0) else None)
        else:
            v = conv(d)
        if v is not None:
            out[d["sample_id"]] = v
    return out

rows_out = [["method_task", "temperature", "f1_run1", "f1_run2", "f1_run3", "f1_mean", "f1_std", "disagreement_rate", "n_common"]]
for group in GROUPS:
    for T in (0.0, 0.3, 0.7):
        sel = json.load(open(os.path.join(BASE, group, "selected_300_ids.json")))
        labels = {s: m["label"] for s, m in sel.items()} if isinstance(next(iter(sel.values())), dict) else {}
        allowed = set(sel)
        try:
            runs = [load(group, T, r, allowed) for r in (1, 2, 3)]
        except FileNotFoundError as e:
            print(f"skip {group} T={T}: {e.filename}")
            continue
        # paper caliber: one COMMON SET per group = samples validly parsed in ALL runs
        # across ALL temperatures (so every temperature is computed on identical samples)
        try:
            all_runs_all_T = []
            for T2 in (0.0, 0.3, 0.7):
                for r2 in (1, 2, 3):
                    all_runs_all_T.append(set(load(group, T2, r2, allowed)))
            group_common = set.intersection(*all_runs_all_T) & allowed
        except FileNotFoundError:
            group_common = set.intersection(*[set(x) for x in runs]) & allowed
        common = sorted(group_common)
        if not common:
            continue
        f1s = []
        for run in runs:
            tp = sum(1 for s in common if run[s] == 1 and labels.get(s, 0) == 1)
            fp = sum(1 for s in common if run[s] == 1 and labels.get(s, 0) == 0)
            fn = sum(1 for s in common if run[s] == 0 and labels.get(s, 0) == 1)
            f1s.append(2*tp/max(2*tp+fp+fn, 1))
        M = np.array([[run[s] for run in runs] for s in common], dtype=float)
        dis = float(np.mean(M.max(axis=1) != M.min(axis=1)))
        rows_out.append([group, T] + [f"{x:.4f}" for x in f1s] +
                        [f"{np.mean(f1s):.4f}", f"{np.std(f1s, ddof=1):.4f}", f"{dis:.4f}", len(common)])
        print(f"{group} T={T}: F1={np.mean(f1s):.4f}±{np.std(f1s, ddof=1):.4f} dis={dis*100:.1f}% n={len(common)}")

with open(OUT, "w", newline="") as f:
    csv.writer(f).writerows(rows_out)
print("wrote", OUT)
