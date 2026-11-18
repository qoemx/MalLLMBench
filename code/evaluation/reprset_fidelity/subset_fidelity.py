#!/usr/bin/env python3
"""M2 ReprSet fidelity — Cryptojacking. Reads ONLY repo-relative shipped files.
100 stratified draws × 5 sizes; E = |F1_sub − F1_full| for PE2 & AV-Agent (final)."""
import csv, json, random, os
import numpy as np

os.makedirs("results/reprset_fidelity", exist_ok=True)

# ---- labels from manifests ----
wild_lab, wild_cat = {}, {}
for row in csv.DictReader(open("data/manifests/cryptojacking_wild.csv")):
    h = (row.get("hash") or row["filename"])[:16]
    if row.get("source") == "benign":
        wild_lab[h] = 0; wild_cat[h] = "benign"
    else:
        wild_lab[h] = int(row["label"])
        wild_cat[h] = "cryptojacking" if int(row["label"]) == 1 else "other_malware"

def load_pred(fn):
    m = {}
    for r in csv.DictReader(open(fn)):
        p = r["prediction"]
        p = 1 if str(p) in ("1", "cryptominer", "ransomware") else 0
        m[r["sample_id"]] = p
    return m

pe2 = load_pred("results/predictions/pe2_cryptojacking_wild_predictions.csv")
av = load_pred("results/predictions/avagent_cryptojacking_wild_predictions.csv")
pool = [h for h in wild_lab if h in pe2 and h in av]
cats_pool = {"cryptojacking": [], "other_malware": [], "benign": []}
for h in pool:
    cats_pool[wild_cat[h]].append(h)
N_POOL = len(pool)
print(f"pool {N_POOL}")

def f1_of(ids, pm):
    tp = sum(1 for h in ids if pm[h] == 1 and wild_lab[h] == 1)
    fp = sum(1 for h in ids if pm[h] == 1 and wild_lab[h] == 0)
    fn = sum(1 for h in ids if pm[h] == 0 and wild_lab[h] == 1)
    return 2*tp/max(2*tp+fp+fn, 1)

F_pe2, F_av = f1_of(pool, pe2), f1_of(pool, av)
print(f"full F1: PE2={F_pe2:.4f} AV={F_av:.4f}")

rows, summary = [], {}
for N in (500, 1000, 1500, 2000, 3000):
    frac = {c: len(v)/N_POOL for c, v in cats_pool.items()}
    n_cat = {c: max(1, round(N*frac[c])) for c in cats_pool}
    n_cat["other_malware"] += N - sum(n_cat.values())
    eps, eas, joint = [], [], []
    for seed in range(100):
        random.seed(seed)
        sub = []
        for c, n in n_cat.items():
            sub += random.sample(cats_pool[c], n)
        e1, e2 = abs(f1_of(sub, pe2)-F_pe2), abs(f1_of(sub, av)-F_av)
        eps.append(e1); eas.append(e2); joint.append(max(e1, e2))
        rows.append([N, seed, f1_of(sub, pe2), e1, f1_of(sub, av), e2, max(e1, e2), max(e1, e2) <= 0.05])
    eps, eas, joint = map(np.array, (eps, eas, joint))
    summary[N] = dict(ep_mean=eps.mean(), ep_q95=np.percentile(eps, 95), ea_mean=eas.mean(),
                      ea_q95=np.percentile(eas, 95), joint_q95=np.percentile(joint, 95),
                      pass_rate=float(np.mean(joint <= 0.05)), save=1 - N/N_POOL)
    print(f"N={N}: pass={summary[N]['pass_rate']*100:.0f}%")

with open("results/reprset_fidelity/cryptojacking_subsets.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["N","seed","f1_pe2_sub","E_pe2","f1_av_sub","E_av","E_joint","pass"])
    w.writerows(rows)
json.dump({str(k): {kk: float(vv) for kk, vv in v.items()} for k, v in summary.items()},
          open("results/reprset_fidelity/cryptojacking_summary.json", "w"), indent=2)
print("done")
