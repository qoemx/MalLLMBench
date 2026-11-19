#!/usr/bin/env python3
"""实验4: 勒索任务 GI(灰度图163x65) CNN × dataset_v2
恶意GI(shard0 npz) + 良性GI(benign_gi_features.npz) -> v2 Lab五折CNN -> v2 Wild评测"""
import os, json
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

ROOT = "./shared_workspace"
BENIGN = f"{ROOT}/benign_pe"
SEED = 42
torch.manual_seed(SEED)
np.random.seed(SEED)
DEV = "cpu"

def metrics(y, p):
    return (accuracy_score(y, p), precision_score(y, p, zero_division=0),
            recall_score(y, p, zero_division=0), f1_score(y, p, zero_division=0))

# ---- 1. 恶意特征: 论文勒索数据集的 hash -> shard0 md5 npz ----
# shard0 文件名是内容md5, 不是论文hash(md5一致? 论文hash就是VirusShare的md5) → 直接同名找
lab = pd.read_csv(f"{ROOT}/balanced_lab_dataset_1to2.csv")
wild = pd.read_csv(f"{ROOT}/balanced_wild_dataset_1to2.csv")

SHARD = f"{BENIGN}/shard0"
def load_gi(hashes, labels):
    X, y = [], []
    miss = 0
    for h, l in zip(hashes, labels):
        p = os.path.join(SHARD, h + ".npz")
        if not os.path.exists(p):
            miss += 1; continue
        d = np.load(p, allow_pickle=True)
        X.append(d["gi"].reshape(163, 65))
        y.append(l)
    print(f"  加载 {len(X)}, 缺 {miss}")
    return np.array(X, dtype=np.float32), np.array(y)

print("恶意 Lab GI...", flush=True)
XL_m, yL_m = load_gi(lab["hash"].values, lab["label"].values)
print("恶意 Wild GI...", flush=True)
XW_m, yW_m = load_gi(wild["hash"].values, wild["label"].values)

# ---- 2. 良性 ----
d = np.load(f"{BENIGN}/benign_gi_features.npz", allow_pickle=True)
bmap = {h: v for h, v in zip(d["hashes"], d["features"])}
v2l = pd.read_csv(f"{ROOT}/dataset_v2/ransomware_lab.csv")
v2w = pd.read_csv(f"{ROOT}/dataset_v2/ransomware_wild.csv")
XL_b = np.array([bmap[h] for h in v2l[v2l["source"]=="benign"]["hash"] if h in bmap], dtype=np.float32)
XW_b = np.array([bmap[h] for h in v2w[v2w["source"]=="benign"]["hash"] if h in bmap], dtype=np.float32)

XL = np.concatenate([XL_m, XL_b]).reshape(-1, 1, 163, 65)
yL = np.concatenate([yL_m, np.zeros(len(XL_b))])
XW = np.concatenate([XW_m, XW_b]).reshape(-1, 1, 163, 65)
yW = np.concatenate([yW_m, np.zeros(len(XW_b))])
print(f"v2 Lab {XL.shape} 正类{int(yL.sum())} | v2 Wild {XW.shape} 正类{int(yW.sum())}", flush=True)

# ---- 3. CNN (论文: 简单CNN, 163x65) ----
class GICNN(nn.Module):
    def __init__(self):
        super().__init__()
        self.net = nn.Sequential(
            nn.Conv2d(1, 16, 3, padding=1), nn.ReLU(), nn.MaxPool2d(2),
            nn.Conv2d(16, 32, 3, padding=1), nn.ReLU(), nn.MaxPool2d(2),
            nn.Conv2d(32, 64, 3, padding=1), nn.ReLU(), nn.AdaptiveAvgPool2d(1),
            nn.Flatten(), nn.Linear(64, 2))
    def forward(self, x): return self.net(x)

def train_eval_fold(Xtr, ytr, Xte, yte, epochs=40, bs=32):
    model = GICNN()
    opt = torch.optim.Adam(model.parameters(), lr=2e-3)
    sched = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=40)
    lossf = nn.CrossEntropyLoss()
    tr = DataLoader(TensorDataset(torch.tensor(Xtr), torch.tensor(ytr).long()), batch_size=bs, shuffle=True)
    model.train()
    for ep in range(epochs):
        for xb, yb in tr:
            opt.zero_grad(); loss = lossf(model(xb), yb); loss.backward(); opt.step()
        sched.step()
    model.eval()
    with torch.no_grad():
        def pred(X):
            out = []
            for i in range(0, len(X), 256):
                out.append(model(torch.tensor(X[i:i+256])).softmax(1)[:,1].numpy())
            return np.concatenate(out)
        return pred(Xte), pred(XW)

skf = StratifiedKFold(5, shuffle=True, random_state=SEED)
wild_probs = np.zeros(len(XW))
lab_m = []
for f, (tr, te) in enumerate(skf.split(XL, yL), 1):
    pl, pw = train_eval_fold(XL[tr], yL[tr], XL[te], yL[te])
    lab_m.append(metrics(yL[te], (pl>0.5).astype(int)))
    wild_probs += pw / 5
    print(f"fold{f}: Lab {tuple(round(m,4) for m in lab_m[-1])}", flush=True)

pw = (wild_probs > 0.5).astype(int)
mw_ = metrics(yW, pw)
lm = np.mean(lab_m, axis=0)
print("\n===== 勒索任务 GI-CNN v2 结果 =====")
print(f"Lab (五折平均): ACC={lm[0]:.4f} PRE={lm[1]:.4f} REC={lm[2]:.4f} F1={lm[3]:.4f}")
print(f"Wild:          ACC={mw_[0]:.4f} PRE={mw_[1]:.4f} REC={mw_[2]:.4f} F1={mw_[3]:.4f}")
print("\n对照论文 v1: Lab GI .8628/.8076/.7725/.7897 | Wild GI .7521/.7210/.4182/.5294")
bm = np.concatenate([np.zeros(len(XW_m), bool), np.ones(len(XW_b), bool)])
print(f"\n附加: 良性FPR = {(pw[bm]==1).mean():.4f} ({(pw[bm]==1).sum()}/{bm.sum()})")
