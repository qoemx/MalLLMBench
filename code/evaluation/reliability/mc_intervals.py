#!/usr/bin/env python3
"""AV-Agent Phase2 三温度MC区间测算(复用PE2的MC程序框架):
300样本(289共同集, 与PE2口径一致=三次观测齐全)
输出: sample_prediction_probabilities / monte_carlo_metrics / performance_interval_summary / error_transition → av_mc_analysis/
终端只打印汇总"""
import json, csv, os
import numpy as np
from collections import defaultdict

B = "./workspace"
OUT = f"{B}/av_mc_analysis"
os.makedirs(OUT, exist_ok=True)
SEED = 42
N_MC = 10000

sel = json.load(open(f"{B}/repeat_v2_selected_300.json"))
runs = {}
meta = {}
for T in (0.0, 0.3, 0.7):
    for rid in (1, 2, 3):
        runs[(T, rid)] = {}
        if T == 0.0:
            fn = f"{B}/avagent_p2_repeat300_run{rid}.jsonl"
        else:
            fn = f"{B}/avagent_p2_temp_T{T}_run{rid}.jsonl"
        for l in open(fn):
            d = json.loads(l)
            if d.get("prediction") is not None:
                runs[(T, rid)][d["sample_id"]] = d["prediction"]
                meta[d["sample_id"]] = (d["category"], d["label"])

valid = [{s for s, v in r.items() if v is not None} for r in runs.values()]
common = sorted(set(sel) & set.intersection(*valid))
labels = np.array([meta[s][1] for s in common])
cats = [meta[s][0] for s in common]
print(f"共同样本: {len(common)}")

mats_all, freqs = {}, {}
for T in (0.0, 0.3, 0.7):
    M = np.array([[runs[(T, r)][s] for r in (1, 2, 3)] for s in common], dtype=float)
    mats_all[T] = M
    freqs[T] = M.mean(axis=1)
    print(f"T={T}: 不一致率 {np.mean(M.max(axis=1) != M.min(axis=1))*100:.1f}%")

with open(f"{OUT}/sample_prediction_probabilities.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["sample_id","category","label","n_runs","pos_count_T0","pos_count_T0.3","pos_count_T0.7",
                "emp_prob_T0","emp_prob_T0.3","emp_prob_T0.7","smooth_prob_T0","smooth_prob_T0.3","smooth_prob_T0.7"])
    for i, s in enumerate(common):
        c, lb = meta[s]
        pc = {T: int(round(freqs[T][i]*3)) for T in (0.0,0.3,0.7)}
        sm = {T: (pc[T]+1)/5 for T in (0.0,0.3,0.7)}
        w.writerow([s,c,lb,3,pc[0.0],pc[0.3],pc[0.7],
                    f"{freqs[0.0][i]:.4f}",f"{freqs[0.3][i]:.4f}",f"{freqs[0.7][i]:.4f}",
                    f"{sm[0.0]:.4f}",f"{sm[0.3]:.4f}",f"{sm[0.7]:.4f}"])

rng = np.random.default_rng(SEED)
def mc_sim(p_vec, smooth=False):
    p = (p_vec*3+1)/5 if smooth else p_vec
    draws = rng.random((N_MC, len(p))) < p[None,:]
    tp = (draws & (labels==1)[None,:]).sum(axis=1)
    fp = (draws & (labels==0)[None,:]).sum(axis=1)
    fn = ((~draws) & (labels==1)[None,:]).sum(axis=1)
    tn = ((~draws) & (labels==0)[None,:]).sum(axis=1)
    return dict(TP=tp,FP=fp,FN=fn,PRE=tp/np.maximum(tp+fp,1),REC=tp/np.maximum(tp+fn,1),
                F1=2*tp/np.maximum(2*tp+fp+fn,1),ACC=(tp+tn)/len(labels))

real_f1 = {}
for T in (0.0,0.3,0.7):
    f1s = []
    for r in (1,2,3):
        preds = np.array([runs[(T,r)][s] for s in common])
        tp = int(((preds==1)&(labels==1)).sum()); fp = int(((preds==1)&(labels==0)).sum())
        fn = int(((preds==0)&(labels==1)).sum()); tn = int(((preds==0)&(labels==0)).sum())
        f1s.append(2*tp/max(2*tp+fp+fn,1))
    real_f1[T] = (np.mean(f1s), np.std(f1s, ddof=1), f1s)

mc_rows, summary_rows = [], []
for T in (0.0,0.3,0.7):
    for smooth in (False,True):
        res = mc_sim(freqs[T], smooth)
        tag = "smooth" if smooth else "raw"
        q = np.percentile(res["F1"],[2.5,97.5])
        mc_rows.append([T,tag,res["F1"].mean(),res["F1"].std(),q[0],q[1],
                        res["PRE"].mean(),res["REC"].mean(),res["ACC"].mean(),
                        res["TP"].mean(),res["FP"].mean(),res["FN"].mean()])
        if not smooth:
            rm, rs, _ = real_f1[T]
            summary_rows.append([T,rm,rs,res["F1"].mean(),res["F1"].std(),q[0],q[1]])

with open(f"{OUT}/monte_carlo_metrics.csv","w",newline="") as f:
    w = csv.writer(f)
    w.writerow(["temperature","method","F1_mean","F1_std","F1_q2.5","F1_q97.5","PRE_mean","REC_mean","ACC_mean","TP_mean","FP_mean","FN_mean"])
    for r in mc_rows: w.writerow([r[0],r[1]]+[f"{x:.4f}" for x in r[2:]])
with open(f"{OUT}/performance_interval_summary.csv","w",newline="") as f:
    w = csv.writer(f)
    w.writerow(["temperature","real_F1_mean","real_F1_std","mc_F1_mean","mc_F1_std","mc_F1_q2.5","mc_F1_q97.5"])
    for r in summary_rows: w.writerow([r[0]]+[f"{x:.4f}" for x in r[1:]])

err_rows = []
for T in (0.0,0.3,0.7):
    for cat in ("cryptojacking","other_malware","benign"):
        idx = [i for i,c in enumerate(cats) if c==cat]
        sub = mats_all[T][idx].astype(int)
        n = len(idx)
        stable0 = int((sub.max(axis=1)==0).sum()); stable1 = int((sub.min(axis=1)==1).sum())
        mixed = n-stable0-stable1
        lb1 = int(sum(1 for i in idx if labels[i]==1))
        tp_exp = sum(freqs[T][i] for i in idx if labels[i]==1)
        fp_exp = sum(freqs[T][i] for i in idx if labels[i]==0)
        fn_exp = sum(1-freqs[T][i] for i in idx if labels[i]==1)
        err_rows.append([T,cat,n,lb1,stable1,stable0,mixed,
                         tp_exp/max(lb1,1)*100, fp_exp/max(n-lb1,1)*100, fn_exp/max(lb1,1)*100])
with open(f"{OUT}/error_transition_summary.csv","w",newline="") as f:
    w = csv.writer(f)
    w.writerow(["temperature","category","n","n_label1","always_pos","always_neg","mixed","exp_recall_pct","exp_fp_rate_pct","exp_fn_rate_pct"])
    for r in err_rows: w.writerow([r[0],r[1]]+r[2:7]+[f"{x:.1f}" for x in r[7:10]])

print("\n== AV-Agent Phase2 MC区间(289共同集) ==")
for T in (0.0,0.3,0.7):
    rm, rs, f1s = real_f1[T]
    raw = next(r for r in mc_rows if r[0]==T and r[1]=="raw")
    sm = next(r for r in mc_rows if r[0]==T and r[1]=="smooth")
    print(f"T={T}: 真实F1 {rm:.4f}±{rs:.4f} | MC {raw[2]:.4f}±{raw[3]:.4f} [{raw[4]:.4f},{raw[5]:.4f}] | 平滑 {sm[2]:.4f}±{sm[3]:.4f} [{sm[4]:.4f},{sm[5]:.4f}] Δ={sm[2]-raw[2]:+.4f}")
print("\nCSV → av_mc_analysis/ 4文件")
