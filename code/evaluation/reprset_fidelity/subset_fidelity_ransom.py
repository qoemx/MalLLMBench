#!/usr/bin/env python3
"""勒索: (1)AV-Agent最终结果MC区间(复用PE2程序, 三温度×300样本)
       (2)代表性子集规模测算(N=500/1000/1500/2000/3000, 100种子, 双方法E<=0.05)
AV-Agent=最终结果(两阶段输出): 300重复(final) + 温度消融用PE2勒索温度链? 不——
勒索AV-Agent只有T=0三次(300重复). 温度消融没有跑 → MC区间按T=0单温度(三次观测)
PE2勒索=已有三温度(repeat_r链)"""
import json, csv, os, random
import numpy as np

B = "./workspace"

# ============ Part 1: AV-Agent最终结果 MC区间(T=0, 300样本三次) ============
OUT1 = f"{B}/av_r_mc_analysis"
os.makedirs(OUT1, exist_ok=True)
sel = json.load(open(f"{B}/repeat_r_selected_300.json"))
runs = {}
meta = {}
for rid in (1, 2, 3):
    runs[rid] = {}
    for l in open(f"{B}/avagent_r_repeat300_run{rid}.jsonl"):
        d = json.loads(l)
        if d.get("final") is not None:
            runs[rid][d["sample_id"]] = d["final"]
            meta[d["sample_id"]] = (d["category"], d["label"])
common = sorted(set(sel) & set.intersection(*[set(r) for r in runs.values()]))
labels = np.array([meta[s][1] for s in common])
cats = [meta[s][0] for s in common]
M = np.array([[runs[r][s] for r in (1,2,3)] for s in common], dtype=float)
freqs = M.mean(axis=1)
print(f"== AV-Agent勒索最终结果 MC(T=0, n={len(common)}) ==")

SEED = 42; N_MC = 10000
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

f1s_real = []
for r in (1,2,3):
    preds = np.array([runs[r][s] for s in common])
    tp = int(((preds==1)&(labels==1)).sum()); fp = int(((preds==1)&(labels==0)).sum())
    fn = int(((preds==0)&(labels==1)).sum())
    f1s_real.append(2*tp/max(2*tp+fp+fn,1))

mc_rows = []
for smooth in (False, True):
    res = mc_sim(freqs, smooth)
    q = np.percentile(res["F1"], [2.5, 97.5])
    tag = "smooth" if smooth else "raw"
    mc_rows.append([0.0, tag, res["F1"].mean(), res["F1"].std(), q[0], q[1],
                    res["PRE"].mean(), res["REC"].mean(), res["ACC"].mean(),
                    res["TP"].mean(), res["FP"].mean(), res["FN"].mean()])

with open(f"{OUT1}/monte_carlo_metrics.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["temperature","method","F1_mean","F1_std","F1_q2.5","F1_q97.5","PRE_mean","REC_mean","ACC_mean","TP_mean","FP_mean","FN_mean"])
    for r in mc_rows: w.writerow([r[0], r[1]] + [f"{x:.4f}" for x in r[2:]])
with open(f"{OUT1}/performance_interval_summary.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["temperature","real_F1_mean","real_F1_std","mc_F1_mean","mc_F1_std","mc_F1_q2.5","mc_F1_q97.5"])
    w.writerow([0.0, f"{np.mean(f1s_real):.4f}", f"{np.std(f1s_real, ddof=1):.4f}",
                f"{mc_rows[0][2]:.4f}", f"{mc_rows[0][3]:.4f}", f"{mc_rows[0][4]:.4f}", f"{mc_rows[0][5]:.4f}"])
with open(f"{OUT1}/sample_prediction_probabilities.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["sample_id","category","label","n_runs","pos_count_T0","emp_prob_T0","smooth_prob_T0"])
    for i, s in enumerate(common):
        c, lb = meta[s]
        pc = int(round(freqs[i]*3))
        w.writerow([s, c, lb, 3, pc, f"{freqs[i]:.4f}", f"{(pc+1)/5:.4f}"])

raw, sm = mc_rows[0], mc_rows[1]
print(f"真实F1 {np.mean(f1s_real):.4f}±{np.std(f1s_real, ddof=1):.4f} (逐次{[f'{x:.4f}' for x in f1s_real]})")
print(f"MC {raw[2]:.4f}±{raw[3]:.4f} [{raw[4]:.4f},{raw[5]:.4f}] | 平滑 {sm[2]:.4f}±{sm[3]:.4f} [{sm[4]:.4f},{sm[5]:.4f}] Δ={sm[2]-raw[2]:+.4f}")
print(f"CSV → {OUT1}/ 3文件\n")

# ============ Part 2: 勒索代表性子集(双方法) ============
v2 = {}
v2cat = {}
for row in csv.DictReader(open("./data/manifests/ransomware_wild_v2.csv")):
    h = row["hash"].removesuffix(".exe")[:16]
    if row.get("source") == "benign":
        v2[h] = 0; v2cat[h] = "benign"
    else:
        v2[h] = int(row["label"]); v2cat[h] = "ransomware" if int(row["label"]) == 1 else "other_malware"

# PE2勒索最终=投票版(论文勒索口径)
pe2 = {}
for l in open(f"{B}/pe2p_ransom_07p_clean_results.jsonl"):
    d = json.loads(l)
    if d.get("status") == "success":
        pe2[d["sample_id"]] = 1 if d["prediction"] == "ransomware" else 0
for l in open(f"{B}/pe2p_ransom_qwen38-27b_run2_results.jsonl"):
    d = json.loads(l)
    if d.get("status") == "success" and d["sample_id"] not in pe2:
        pe2[d["sample_id"]] = 1 if d["prediction"] == "ransomware" else 0
# PE2勒索用投票版(更强的那版)
pe2v = {}
for l in open(f"{B}/pe2p_ransom_ult_clean_results.jsonl"):
    d = json.loads(l)
    if d.get("status") == "success":
        pe2v[d["sample_id"]] = d["prediction"]
for l in open(f"{B}/pe2p_ultimate_ransom_results.jsonl"):
    d = json.loads(l)
    if d.get("status") == "success" and d["sample_id"] not in pe2v:
        pe2v[d["sample_id"]] = d["prediction"]

# AV-Agent勒索最终
av = {}
for l in open(f"{B}/avagent_ransom_v2_phase1_results.jsonl"):
    d = json.loads(l)
    if d.get("prediction") is not None:
        av[d["sample_id"][:16]] = d["prediction"]
for l in open(f"{B}/avagent_ransom_v2_phase2_results.jsonl"):
    d = json.loads(l)
    if d.get("prediction") is not None:
        av[d["sample_id"][:16]] = d["prediction"]

pool = [h for h in v2 if h in pe2v and h in av]
cats_pool = {"ransomware": [], "other_malware": [], "benign": []}
for h in pool:
    cats_pool[v2cat[h]].append(h)
N_POOL = len(pool)
print(f"== 勒索子集实验: 全量池 {N_POOL} ==")

def f1_of(ids, pm):
    tp = sum(1 for h in ids if pm[h] == 1 and v2[h] == 1)
    fp = sum(1 for h in ids if pm[h] == 1 and v2[h] == 0)
    fn = sum(1 for h in ids if pm[h] == 0 and v2[h] == 1)
    return 2*tp/max(2*tp+fp+fn, 1)

F_pe2 = f1_of(pool, pe2v)
F_av = f1_of(pool, av)
print(f"全量F1: PE2(投票)={F_pe2:.4f} AV-Agent(最终)={F_av:.4f}")

rows_out = []
summary = {}
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
        fp_ = abs(f1_of(sub, pe2v) - F_pe2)
        fa_ = abs(f1_of(sub, av) - F_av)
        e = max(fp_, fa_)
        eps.append(fp_); eas.append(fa_); joint.append(e)
        rows_out.append([N, seed, f1_of(sub, pe2v), fp_, f1_of(sub, av), fa_, e, e <= 0.05])
    eps, eas, joint = np.array(eps), np.array(eas), np.array(joint)
    summary[N] = dict(ep_mean=eps.mean(), ep_q95=np.percentile(eps, 95),
                      ea_mean=eas.mean(), ea_q95=np.percentile(eas, 95),
                      joint_q95=np.percentile(joint, 95),
                      pass_rate=np.mean(joint <= 0.05), save=1 - N/N_POOL)
    print(f"N={N}: E_PE2均值={eps.mean():.4f}/q95={np.percentile(eps,95):.4f} | E_AV均值={eas.mean():.4f}/q95={np.percentile(eas,95):.4f} | 联合q95={np.percentile(joint,95):.4f} | 达标率={np.mean(joint<=0.05)*100:.0f}%")

print("\n== 勒索最终结果表 ==")
print("| 子集规模 | PE2 F1误差(均值/q95) | AV-Agent F1误差(均值/q95) | 同时达标率(E≤0.05) | 节省率 |")
for N, s in summary.items():
    print(f"| {N} | {s['ep_mean']:.4f} / {s['ep_q95']:.4f} | {s['ea_mean']:.4f} / {s['ea_q95']:.4f} | {s['pass_rate']*100:.0f}% | {s['save']*100:.1f}% |")

# 固定最优子集: 最小规模使达标率>=95%
best = None
for N in (500, 1000, 1500, 2000, 3000):
    if summary[N]["pass_rate"] >= 0.95:
        best = N; break
if best is None: best = 3000
frac = {c: len(v)/N_POOL for c, v in cats_pool.items()}
n_cat = {c: max(1, round(best*frac[c])) for c in cats_pool}
n_cat["other_malware"] += best - sum(n_cat.values())
random.seed(42)
final_meta = []
for c, n in n_cat.items():
    for h in random.sample(cats_pool[c], n):
        final_meta.append([h, c, v2[h]])
json.dump(final_meta, open(f"{B}/representative_subset_ransom_{best}.json", "w"), indent=1)
print(f"\n选定勒索子集: {best} → representative_subset_ransom_{best}.json")

with open(f"{B}/subset_ransom_detail.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["N","seed","f1_pe2_sub","E_pe2","f1_av_sub","E_av","E_joint","pass"])
    w.writerows(rows_out)
json.dump({str(k): {kk: float(vv) for kk, vv in v.items()} for k, v in summary.items()},
          open(f"{B}/subset_ransom_summary.json", "w"), indent=2)
print("subset_ransom_detail.csv / subset_ransom_summary.json saved")
