#!/usr/bin/env python3
"""RB(MalConv) 置信度+权重补存 — 原版 malconv_v2.py 逐字复刻
唯一差异: 保存每折权重 + wild置信度CSV(带filename/is_benign)
用法: python3 rb_standalone.py miner|ransom"""
import os, sys, json, time, glob
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

BASE = "/home/aapt/disk1.7T/aapt-u1_data"
LAB = "./data/manifests"
OUT = f"{BASE}/work/artifacts"
DEV = 'cuda' if torch.cuda.is_available() else 'cpu'
SEED = 42

def metrics(y, p):
    return (accuracy_score(y, p), precision_score(y, p, zero_division=0),
            recall_score(y, p, zero_division=0), f1_score(y, p, zero_division=0))

def index_malware():  # 原版逐字: 两层嵌套递归glob
    m = {}
    for sub in ['挖矿', '挖矿白样本']:
        for p in glob.glob(f'{BASE}/miner_task_bin/{sub}/**/VirusShare_*', recursive=True):
            h = os.path.basename(p).replace('VirusShare_', '')
            m[h] = p
    for d in ['wild_ransom_bin', 'wild_nonrw_bin']:
        for p in glob.glob(f'{BASE}/{d}/**/VirusShare_*', recursive=True):
            h = os.path.basename(p).replace('VirusShare_', '')
            m.setdefault(h, p)
    return m

def bytes_to_tensor(path, size=2000000):  # 原版
    with open(path, 'rb') as f: b = f.read(size)
    x = np.zeros(size, dtype=np.int64)
    x[:len(b)] = np.frombuffer(b, dtype=np.uint8).astype(np.int64) + 1
    return torch.from_numpy(x)

class PEDataset(Dataset):  # 原版
    def __init__(self, items): self.items = items
    def __len__(self): return len(self.items)
    def __getitem__(self, i):
        p, y = self.items[i]
        return bytes_to_tensor(p), float(y)

class MalConv(nn.Module):  # 原版逐字
    def __init__(self):
        super().__init__()
        self.embed = nn.Embedding(257, 8, padding_idx=0)
        self.conv1 = nn.Conv1d(8, 128, 500, stride=500)
        self.conv2 = nn.Conv1d(8, 128, 500, stride=500)
        self.fc = nn.Linear(128, 1)
    def forward(self, x):
        e = self.embed(x).transpose(1, 2)
        h = self.conv1(e) * torch.sigmoid(self.conv2(e))
        return self.fc(h.max(2).values).squeeze(1)

def infer(model, loader):  # 原版
    model.eval(); ps = []
    with torch.no_grad():
        for xb, _ in loader:
            ps.extend(torch.sigmoid(model(xb.to(DEV))).cpu().numpy())
    return np.array(ps)

def run_task(tag, name, lab_csv, wild_csv, v2lab, v2wild, benign_dir):
    print(f'===== {name} MalConv 置信度补存 =====', flush=True)
    mal = index_malware()
    lab = pd.read_csv(lab_csv); wild = pd.read_csv(wild_csv)
    v2l = pd.read_csv(v2lab); v2w = pd.read_csv(v2wild)
    def build(df, benign_hashes):
        items, fns, bm = [], [], []
        for h, y in zip(df['hash'].astype(str), df['label']):
            if h in mal:
                items.append((mal[h], int(y))); fns.append(h); bm.append(False)
        for h in benign_hashes:
            for p in (f'{benign_dir}/{h}', f'{benign_dir}/{h}.exe'):
                if os.path.exists(p):
                    items.append((p, 0)); fns.append(h.removesuffix('.exe')); bm.append(True); break
        return items, fns, bm
    bl = list(v2l[v2l['source'] == 'benign']['hash'])
    bw = list(v2w[v2w['source'] == 'benign']['hash'])
    lab_items, _, _ = build(lab, bl)
    wild_items, wfn, wbm = build(wild, bw)
    print(f'lab={len(lab_items)} wild={len(wild_items)}', flush=True)

    OUTD = f"{OUT}/{tag}"
    os.makedirs(f"{OUTD}/models", exist_ok=True); os.makedirs(f"{OUTD}/confidence", exist_ok=True)
    yl = np.array([y for _, y in lab_items])
    skf = StratifiedKFold(5, shuffle=True, random_state=SEED)
    wild_probs = np.zeros(len(wild_items)); lab_scores = []
    for f, (tr, te) in enumerate(skf.split(np.zeros(len(yl)), yl), 1):
        torch.manual_seed(SEED)
        model = MalConv().to(DEV)
        opt = torch.optim.Adam(model.parameters(), lr=1e-3)
        pos_w = torch.tensor([(len(tr)-yl[tr].sum())/max(yl[tr].sum(),1)], dtype=torch.float32).to(DEV)
        lf = nn.BCEWithLogitsLoss(pos_weight=pos_w)
        tr_loader = DataLoader(PEDataset([lab_items[i] for i in tr]), batch_size=4, shuffle=True, num_workers=8)
        te_loader = DataLoader(PEDataset([lab_items[i] for i in te]), batch_size=8, num_workers=4)
        wl_loader = DataLoader(PEDataset(wild_items), batch_size=8, num_workers=4)
        model.train()
        for ep in range(5):
            t0 = time.time()
            for xb, yb in tr_loader:
                xb, yb = xb.to(DEV), yb.float().to(DEV)
                opt.zero_grad(); lf(model(xb), yb).backward(); opt.step()
        torch.save(model.state_dict(), f"{OUTD}/models/fold{f}.pth")
        pl = infer(model, te_loader); wild_probs += infer(model, wl_loader)/5
        lab_scores.append(metrics(yl[te], (pl > 0.5).astype(int)))
        print(f'fold{f}: {tuple(round(x,4) for x in lab_scores[-1])}', flush=True)
    pw = (wild_probs > 0.5).astype(int)
    yw = np.array([y for _, y in wild_items])
    bm = np.array(wbm)
    pd.DataFrame({"filename": wfn, "label": yw, "prob": wild_probs, "pred": pw, "is_benign": bm}
                 ).to_csv(f"{OUTD}/confidence/wild_v2_confidence.csv", index=False)
    lm = np.mean(lab_scores, axis=0); wm = metrics(yw, pw)
    fpr = float(pw[bm].mean())
    print(f'[{tag}] Lab F1={lm[3]:.4f} Wild F1={wm[3]:.4f} 良性FPR={fpr:.4f}', flush=True)
    json.dump(dict(name=tag, lab=[round(x,4) for x in lm], wild=[round(x,4) for x in wm], benign_fpr=round(fpr,4)),
              open(f"{OUTD}/results.json", "w"))

if __name__ == '__main__':
    which = sys.argv[1]
    if which == 'miner':
        run_task('crypto_RB', '挖矿', f'{LAB}/lab_label.csv', f'{LAB}/wild_label.csv',
                 f'{LAB}/cryptojacking_lab_v2.csv', f'{LAB}/cryptojacking_wild_v2.csv',
                 '/home/aapt-u1/v2_benign_in')
    else:
        # 勒索: 原版malconv_ransom_v2.py口径
        run_task('ransom_RB', '勒索', f'{LAB}/balanced_lab_dataset_1to2.csv', f'{LAB}/balanced_wild_dataset_1to2.csv',
                 f'{LAB}/ransomware_lab_v2.csv', f'{LAB}/ransomware_wild_v2.csv',
                 f'{BASE}/v2_benign_in_r')
    print("RB_STANDALONE_DONE")
