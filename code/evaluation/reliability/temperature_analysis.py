#!/usr/bin/env python3
"""勒索AV-Agent温度消融终算: T=0/0.3/0.7 × 3次完整管线
四类输出: (1)三次真实指标+F1均值±std (2)分层不一致率 (3)MC区间 (4)MCvs真实对照"""
import json, csv, os
import numpy as np
from collections import Counter

B = "./workspace"
OUT = f"{B}/av_r_temp_analysis"
os.makedirs(OUT, exist_ok=True)
SEED = 42
N_MC = 10000

sel = json.load(open(f"{B}/repeat_r_selected_300.json"))

runs = {}
meta = {}
for T in (0.0, 0.3, 0.7):
    for rid in (1, 2, 3):
        runs[(T, rid)] = {}
        if T == 0.0:
            fn = f"{B}/avagent_r_repeat300_run{rid}.jsonl"
        else:
            fn = f"{B}/avagent_r_temp_T{T}_run{rid}.jsonl"
        for l in open(fn):
            d = json.loads(l)
            if d.get("final") is not None:
                runs[(T, rid)][d["sample_id"]] = d["final"]
                meta[d["sample_id"]] = (d["category"], d["label"])

valid = [{s for s, v in r.items() if v is not None} for r in runs.values()]
common = sorted(set(sel) & set.intersection(*valid))
labels = np.array([meta[s][1] for s in common])
cats = [meta[s][0] for s in common]
print(f"共同样本: {len(common)}")

rng = np.random.default_rng(SEED)

print("\n(1) 三次真实指标 + F1均值±std")
print("(2) 分层不一致率")
print("(3) MC区间")
all_data = {}
for T in (0.0, 0.3, 0.7):
    f1s = []
    print(f"\n== T={T} ==")
    for r in (1, 2, 3):
        preds = np.array([runs[(T, r)][s] for s in common])
        tp = int(((preds==1)&(labels==1)).sum()); fp = int(((preds==1)&(labels==0)).sum())
        fn = int(((preds==0)&(labels==1)).sum()); tn = int(((preds==0)&(labels==0)).sum())
        f1 = 2*tp/max(2*tp+fp+fn, 1)
        f1s.append(f1)
        print(f"  run{r}: ACC={(tp+tn)/len(common):.4f} PRE={tp/max(tp+fp,1):.4f} REC={tp/max(tp+fn,1):.4f} F1={f1:.4f} (TP{tp} FP{fp} FN{fn} TN{tn})")
    mean_f1 = np.mean(f1s); std_f1 = np.std(f1s, ddof=1)
    print(f"  F1均值: {mean_f1:.4f}±{std_f1:.4f}")

    M = np.array([[runs[(T, r)][s] for r in (1,2,3)] for s in common], dtype=float)
    inconv = np.mean(M.max(axis=1) != M.min(axis=1))
    line = f"  不一致率: 总{inconv*100:.1f}%"
    for cat in ("ransomware", "other_malware", "benign"):
        idx = [i for i, c in enumerate(cats) if c == cat]
        sub = M[idx]
        d = np.mean(sub.max(axis=1) != sub.min(axis=1))
        line += f" | {cat} {d*100:.1f}%"
    print(line)

    freqs = M.mean(axis=1)
    draws = rng.random((N_MC, len(freqs))) < freqs[None, :]
    tp_mc = (draws & (labels==1)[None,:]).sum(axis=1)
    fp_mc = (draws & (labels==0)[None,:]).sum(axis=1)
    fn_mc = ((~draws) & (labels==1)[None,:]).sum(axis=1)
    tn_mc = ((~draws) & (labels==0)[None,:]).sum(axis=1)
    f1_mc = 2*tp_mc/np.maximum(2*tp_mc+fp_mc+fn_mc, 1)
    q = np.percentile(f1_mc, [2.5, 97.5])
    # 平滑
    p_sm = (freqs*3+1)/5
    draws_s = rng.random((N_MC, len(p_sm))) < p_sm[None, :]
    tp_s = (draws_s & (labels==1)[None,:]).sum(axis=1)
    fp_s = (draws_s & (labels==0)[None,:]).sum(axis=1)
    fn_s = ((~draws_s) & (labels==1)[None,:]).sum(axis=1)
    f1_s = 2*tp_s/np.maximum(2*tp_s+fp_s+fn_s, 1)
    q_s = np.percentile(f1_s, [2.5, 97.5])
    print(f"  MC: {f1_mc.mean():.4f}±{f1_mc.std():.4f} 95%区间[{q[0]:.4f},{q[1]:.4f}] (平滑 {f1_s.mean():.4f}±{f1_s.std():.4f} [{q_s[0]:.4f},{q_s[1]:.4f}] Δ={f1_s.mean()-f1_mc.mean():+.4f})")
    # (4) 对照
    ratio = f1_mc.std()/max(std_f1, 1e-9) if std_f1 > 0 else float('inf')
    print(f"  对照: 真实std={std_f1:.4f} vs MC std={f1_mc.std():.4f} (MC/真实={ratio:.1f}x) | MC均值-真实均值={f1_mc.mean()-mean_f1:+.4f}")
    all_data[str(T)] = dict(f1_runs=[round(x,4) for x in f1s], f1_mean=round(mean_f1,4),
                            f1_std=round(std_f1,4), disagreement=round(inconv,4),
                            mc_mean=round(f1_mc.mean(),4), mc_std=round(f1_mc.std(),4),
                            mc_q2_5=round(q[0],4), mc_q97_5=round(q[1],4),
                            mc_smooth_mean=round(f1_s.mean(),4), mc_smooth_q2_5=round(q_s[0],4),
                            mc_smooth_q97_5=round(q_s[1],4))

json.dump(all_data, open(f"{OUT}/av_r_temp_summary.json", "w"), indent=2)

# CSV输出
with open(f"{OUT}/performance_interval_summary.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["temperature","real_F1_mean","real_F1_std","mc_F1_mean","mc_F1_std","mc_F1_q2.5","mc_F1_q97.5","disagreement"])
    for T, d in all_data.items():
        w.writerow([T, d["f1_mean"], d["f1_std"], d["mc_mean"], d["mc_std"], d["mc_q2_5"], d["mc_q97_5"], d["disagreement"]])

with open(f"{OUT}/sample_prediction_probabilities.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["sample_id","category","label"]+[f"pos_count_T{T}" for T in (0.0,0.3,0.7)]+[f"emp_prob_T{T}" for T in (0.0,0.3,0.7)])
    mats = {T: np.array([[runs[(T,r)][s] for r in (1,2,3)] for s in common], dtype=float) for T in (0.0,0.3,0.7)}
    for i, s in enumerate(common):
        c, lb = meta[s]
        pcs = [int(round(mats[T][i].mean()*3)) for T in (0.0,0.3,0.7)]
        w.writerow([s, c, lb] + pcs + [f"{mats[T][i].mean():.4f}" for T in (0.0,0.3,0.7)])
print(f"\nCSV+JSON → {OUT}/")
print("AV_R_TEMP_ANALYSIS_DONE")
