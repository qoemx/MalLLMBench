#!/usr/bin/env python3
"""实验二正式版: 代表性子集规模测算(N=500/1000/1500/2000/3000, 每规模100种子)
- 分层随机抽样(真实类别比例), 不用预测/聚类
- E_m(N)=|F1_sub-F1_full|; E(N)=max(E_PE2, E_Agent)
- AV-Agent=最终结果(Phase1+2全链路输出=.8475口径)
- 达标: E(N)<=0.05
- 输出: 最终一张表 + 逐次明细CSV"""
import json, csv, random
import numpy as np

B = "/home/aapt/disk1.7T/aapt-u1_data/work/pe2prompt"

wild_lab = {}
wild_cat = {}
for row in csv.DictReader(open("/home/aapt-u1/v2data/labels/wild_label.csv")):
    wild_lab[row["hash"][:16]] = int(row["label"])
    wild_cat[row["hash"][:16]] = "cryptojacking" if int(row["label"]) == 1 else "other_malware"
for row in csv.DictReader(open("/home/aapt-u1/v2data/labels/cryptojacking_wild_v2.csv")):
    if row.get("source") == "benign":
        wild_lab[row["hash"].removesuffix(".exe")[:16]] = 0
        wild_cat[row["hash"].removesuffix(".exe")[:16]] = "benign"

pe2 = {}
for l in open(f"{B}/pe2p_miner_qwen38-27b_run1_results.jsonl"):
    d = json.loads(l)
    if d.get("status") == "success":
        pe2[d["sample_id"]] = 1 if d["prediction"] == "cryptominer" else 0
for l in open(f"{B}/pe2_miner_v2wild_backfill.jsonl"):
    d = json.loads(l)
    if d.get("status") == "success":
        pe2[d["sample_id"]] = 1 if d["prediction"] == "cryptominer" else 0

# AV-Agent 最终结果 = Phase1+2 全链路(Phase2输出优先, 无则Phase1)
av_final = {}
for l in open(f"{B}/avagent_miner_v2_phase1_results.jsonl"):
    d = json.loads(l)
    if d.get("prediction") is not None:
        av_final[d["sample_id"][:16]] = d["prediction"]
for l in open(f"{B}/avagent_miner_v2_phase2_results.jsonl"):
    d = json.loads(l)
    if d.get("prediction") is not None:
        av_final[d["sample_id"][:16]] = d["prediction"]

pool = [h for h in wild_lab if h in pe2 and h in av_final]
cats_pool = {"cryptojacking": [], "other_malware": [], "benign": []}
for h in pool:
    cats_pool[wild_cat[h]].append(h)
N_POOL = len(pool)
print(f"全量池: {N_POOL}")

def f1_of(ids, pm):
    tp = sum(1 for h in ids if pm[h] == 1 and wild_lab[h] == 1)
    fp = sum(1 for h in ids if pm[h] == 1 and wild_lab[h] == 0)
    fn = sum(1 for h in ids if pm[h] == 0 and wild_lab[h] == 1)
    return 2 * tp / max(2 * tp + fp + fn, 1)

F_pe2 = f1_of(pool, pe2)
F_av = f1_of(pool, av_final)
print(f"全量F1: PE2={F_pe2:.4f} AV-Agent(最终)={F_av:.4f}")

rows_out = []
summary = {}
for N in (500, 1000, 1500, 2000, 3000):
    frac = {c: len(v)/N_POOL for c, v in cats_pool.items()}
    n_cat = {c: max(1, round(N * frac[c])) for c in cats_pool}
    n_cat["other_malware"] += N - sum(n_cat.values())
    eps, eas, joint = [], [], []
    for seed in range(100):
        random.seed(seed)
        sub = []
        for c, n in n_cat.items():
            sub += random.sample(cats_pool[c], n)
        fp_ = abs(f1_of(sub, pe2) - F_pe2)
        fa_ = abs(f1_of(sub, av_final) - F_av)
        e = max(fp_, fa_)
        eps.append(fp_); eas.append(fa_); joint.append(e)
        rows_out.append([N, seed, f1_of(sub, pe2), fp_, f1_of(sub, av_final), fa_, e, e <= 0.05])
    eps, eas, joint = np.array(eps), np.array(eas), np.array(joint)
    summary[N] = dict(
        ep_mean=eps.mean(), ep_q95=np.percentile(eps, 95),
        ea_mean=eas.mean(), ea_q95=np.percentile(eas, 95),
        joint_q95=np.percentile(joint, 95),
        pass_rate=np.mean(joint <= 0.05),
        save=1 - N / N_POOL)
    print(f"N={N}: E_PE2均值={eps.mean():.4f} | E_AV均值={eas.mean():.4f} | E联合q95={np.percentile(joint,95):.4f} | 达标率={np.mean(joint<=0.05)*100:.0f}%")

print("\n== 最终结果表 ==")
print("| 子集规模 | PE2 F1误差(均值/q95) | AV-Agent F1误差(均值/q95) | 同时达标率(E≤0.05) | 样本节省率 |")
for N, s in summary.items():
    print(f"| {N} | {s['ep_mean']:.4f} / {s['ep_q95']:.4f} | {s['ea_mean']:.4f} / {s['ea_q95']:.4f} | {s['pass_rate']*100:.0f}% | {s['save']*100:.1f}% |")

with open(f"{B}/subset_exp2_detail.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["N","seed","f1_pe2_sub","E_pe2","f1_av_sub","E_av","E_joint","pass"])
    w.writerows(rows_out)
json.dump({str(k): {kk: float(vv) for kk, vv in v.items()} for k, v in summary.items()},
          open(f"{B}/subset_exp2_summary.json", "w"), indent=2)
print("\nsubset_exp2_detail.csv / subset_exp2_summary.json saved")
