#!/usr/bin/env python3
"""实验2: 挖矿任务 PF 特征 v2 实验
恶意PF(PE_lab/wild_feature.pkl, 已验证与label顺序对齐) + 良性PF(新提npz)
-> v2 Lab 五折训练 LightGBM(xgb,与论文最佳模型一致) -> v2 Wild 评测"""
import pickle
import numpy as np
import pandas as pd
import lightgbm as lgb
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

ROOT = "./shared_workspace"

def metrics(y, p):
    return (accuracy_score(y, p), precision_score(y, p, zero_division=0),
            recall_score(y, p, zero_division=0), f1_score(y, p, zero_division=0))

# ---- 1. 恶意特征 (pkl 与 label csv 顺序对齐已验证) ----
lab = pd.read_csv(f"{ROOT}/Crypto_experient/lab_label.csv")
wild = pd.read_csv(f"{ROOT}/Crypto_experient/wild_label.csv")
XL_m = np.array(pickle.load(open(f"{ROOT}/Crypto_experient/PE_lab_feature.pkl", "rb")))
XW_m = np.array(pickle.load(open(f"{ROOT}/Crypto_experient/PE_wild_feature.pkl", "rb")))
yL_m, yW_m = lab["label"].values, wild["label"].values
assert len(XL_m) == len(yL_m) and len(XW_m) == len(yW_m)
print(f"恶意 Lab {XL_m.shape}, Wild {XW_m.shape}")

# ---- 2. 良性特征 (v2 划分) ----
d = np.load(f"{ROOT}/benign_pe/benign_pf_features.npz", allow_pickle=True)
benign_map = {h: v for h, v in zip(d["hashes"], d["features"])}
v2l = pd.read_csv(f"{ROOT}/dataset_v2/cryptojacking_lab_v2.csv")
v2w = pd.read_csv(f"{ROOT}/dataset_v2/cryptojacking_wild_v2.csv")
bl = [h for h in v2l[v2l["source"] == "benign"]["hash"] if h in benign_map]
bw = [h for h in v2w[v2w["source"] == "benign"]["hash"] if h in benign_map]
XL_b = np.array([benign_map[h] for h in bl])
XW_b = np.array([benign_map[h] for h in bw])
print(f"良性 Lab {len(XL_b)}, Wild {len(XW_b)}")

# ---- 3. 组装 ----
XL = np.vstack([XL_m, XL_b]); yL = np.concatenate([yL_m, np.zeros(len(XL_b))])
XW = np.vstack([XW_m, XW_b]); yW = np.concatenate([yW_m, np.zeros(len(XW_b))])
print(f"v2 Lab: {XL.shape}, 正类 {int(yL.sum())}")
print(f"v2 Wild: {XW.shape}, 正类 {int(yW.sum())}")

# ---- 4. 五折 LightGBM ----
skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
wild_probs = np.zeros(len(XW))
lab_metrics = []
for fold, (tr, te) in enumerate(skf.split(XL, yL), 1):
    clf = lgb.LGBMClassifier(n_estimators=300, learning_rate=0.1, verbose=-1, random_state=42)
    clf.fit(XL[tr], yL[tr])
    pl = clf.predict(XL[te])
    lab_metrics.append(metrics(yL[te], pl))
    wild_probs += clf.predict_proba(XW)[:, 1] / 5
    print(f"fold{fold}: Lab {tuple(round(m,4) for m in lab_metrics[-1])}", flush=True)

pw = (wild_probs > 0.5).astype(int)
mw_ = metrics(yW, pw)
lm = np.mean(lab_metrics, axis=0)

print("\n===== 挖矿任务 PF(xgb) v2 结果 =====")
print(f"Lab (五折平均): ACC={lm[0]:.4f} PRE={lm[1]:.4f} REC={lm[2]:.4f} F1={lm[3]:.4f}")
print(f"Wild:          ACC={mw_[0]:.4f} PRE={mw_[1]:.4f} REC={mw_[2]:.4f} F1={mw_[3]:.4f}")
print("\n对照论文 v1: Lab PF .9707/.9716/.9400/.9555 | Wild PF .9454/.8846/.9649/.9230")

benign_mask = np.concatenate([np.zeros(len(XW_m), bool), np.ones(len(XW_b), bool)])
print(f"\n附加: 良性子集误报率 FPR = {(pw[benign_mask]==1).mean():.4f} ({(pw[benign_mask]==1).sum()}/{benign_mask.sum()})")
