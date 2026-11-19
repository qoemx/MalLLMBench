#!/usr/bin/env python3
"""实验1: 勒索任务 EH 特征 实验
恶意EH(EHm_result的txt) + 良性EH(新提的npz) -> Lab五折训练 MLP -> Wild评测
输出论文同款指标 ACC/PRE/REC/F1 (与 Table 3/4 勒索EHm列对照)"""
import os
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.neural_network import MLPClassifier

ROOT = "./shared_workspace"

def load_txt_feature(path):
    try:
        return np.loadtxt(path)
    except Exception:
        return None

def metrics(y, p):
    return (accuracy_score(y, p), precision_score(y, p, zero_division=0),
            recall_score(y, p, zero_division=0), f1_score(y, p, zero_division=0))

# ---- 1. 载入恶意特征 ----
def load_malicious(csv_path, feat_dir_lab, feat_dir_wild):
    df = pd.read_csv(csv_path)
    X, y, hashes = [], [], []
    for _, row in df.iterrows():
        h, lbl = row["hash"], row["label"]
        base = feat_dir_lab  # 参数化: lab 或 wild 目录
        p = os.path.join(base, str(lbl), h + ".txt")
        v = load_txt_feature(p)
        if v is not None and len(v) == 512:
            X.append(v); y.append(lbl); hashes.append(h)
    return np.array(X), np.array(y), hashes

print("载入恶意 Lab EH 特征...", flush=True)
XL_m, yL_m, _ = load_malicious(f"{ROOT}/balanced_lab_dataset_1to2.csv",
                                f"{ROOT}/EHm_result/lab_histogram_features", None)
print(f"  {len(XL_m)} 个", flush=True)
print("载入恶意 Wild EH 特征...", flush=True)
# wild 用同函数但目录不同——重写
def load_from_dir(csv_path, base):
    df = pd.read_csv(csv_path)
    X, y, hashes = [], [], []
    for _, row in df.iterrows():
        h, lbl = row["hash"], row["label"]
        p = os.path.join(base, str(lbl), h + ".txt")
        v = load_txt_feature(p)
        if v is not None and len(v) == 512:
            X.append(v); y.append(lbl); hashes.append(h)
    return np.array(X), np.array(y), hashes

XW_m, yW_m, _ = load_from_dir(f"{ROOT}/balanced_wild_dataset_1to2.csv",
                               f"{ROOT}/EHm_result/wild_histogram_features")
print(f"  {len(XW_m)} 个", flush=True)

# ---- 2. 载入良性特征(按 划分) ----
d = np.load(f"{ROOT}/benign_pe/benign_eh_features.npz", allow_pickle=True)
benign_map = {h: v for h, v in zip(d["hashes"], d["features"])}

v2l = pd.read_csv(f"{ROOT}/ransomware_lab.csv")
v2w = pd.read_csv(f"{ROOT}/ransomware_wild.csv")
bl =l[v2l["source"] == "benign"]["hash"].tolist()
bw =w[v2w["source"] == "benign"]["hash"].tolist()

XL_b = np.array([benign_map[h] for h in bl if h in benign_map])
XW_b = np.array([benign_map[h] for h in bw if h in benign_map])
print(f"良性 Lab {len(XL_b)}, Wild {len(XW_b)}", flush=True)

# ---- 3. 组装 ----
XL = np.vstack([XL_m, XL_b]); yL = np.concatenate([yL_m, np.zeros(len(XL_b))])
XW = np.vstack([XW_m, XW_b]); yW = np.concatenate([yW_m, np.zeros(len(XW_b))])
print(f"Lab: {XL.shape}, 正类 {int(yL.sum())}")
print(f"Wild: {XW.shape}, 正类 {int(yW.sum())}")

# ---- 4. 五折训练 + Wild 评测 (EHm: MLP, 与论文一致的简单MLP) ----
skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
wild_probs = np.zeros(len(XW))
lab_metrics = []
fold = 0
for tr, te in skf.split(XL, yL):
    fold += 1
    clf = MLPClassifier(hidden_layer_sizes=(128, 64), max_iter=300, random_state=42)
    clf.fit(XL[tr], yL[tr])
    pl = clf.predict(XL[te])
    lab_metrics.append(metrics(yL[te], pl))
    wild_probs += clf.predict_proba(XW)[:, 1] / 5
    print(f"fold{fold}: Lab {tuple(round(m,4) for m in lab_metrics[-1])}", flush=True)

pw = (wild_probs > 0.5).astype(int)
mw_ = metrics(yW, pw)
lm = np.mean(lab_metrics, axis=0)

print("\n===== 勒索任务 EHm 结果 =====")
print(f"Lab (五折平均): ACC={lm[0]:.4f} PRE={lm[1]:.4f} REC={lm[2]:.4f} F1={lm[3]:.4f}")
print(f"Wild:          ACC={mw_[0]:.4f} PRE={mw_[1]:.4f} REC={mw_[2]:.4f} F1={mw_[3]:.4f}")
print("\n对照论文: Lab EHm .8900/.8641/.7950/.8281 | Wild EHm .7448/.7718/.3328/.4651")

# 良性子集上的 FPR(附加信息)
benign_mask = np.concatenate([np.zeros(len(XW_m), bool), np.ones(len(XW_b), bool)])
print(f"\n附加: 良性子集误报率 FPR = {(pw[benign_mask]==1).mean():.4f} ({(pw[benign_mask]==1).sum()}/{benign_mask.sum()})")
