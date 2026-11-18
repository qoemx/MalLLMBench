#!/usr/bin/env python3
"""EHc v2(两任务) — 原版 EHc_malware_model.py 的 CNN 架构逐字复刻
(MalwareDetector: 512->23x23, Conv60(k2)+MaxPool, Conv200(k2)+MaxPool, Dense500, Sigmoid)
数据: hist_features/{miner,ransom_pos,ransom_neg,benign_miner,benign_ransom} 的512维txt
挖矿: lab=lab_label.csv恶意 + benign_miner(1000) | wild=wild_label.csv + benign_miner(2000)
勒索: lab=ransom标签CSV + benign_ransom | wild=同
五折(StratifiedKFold 42, 原版口径) + Wild均值推理 thr0.5 + 良性FPR
"""
import os, sys, time, glob, csv
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

B = '/home/aapt/disk1.7T/aapt-u1_data'
LAB = './data/manifests'
W = f'{B}/work'
DEV = 'cuda' if torch.cuda.is_available() else 'cpu'
SEED = 42
torch.manual_seed(SEED); np.random.seed(SEED)

class HistDS(Dataset):
    def __init__(self, X, y=None):
        self.X = torch.tensor(X, dtype=torch.float32)
        self.y = torch.tensor(y, dtype=torch.float32) if y is not None else None
    def __len__(self): return len(self.X)
    def __getitem__(self, i):
        if self.y is not None: return self.X[i], self.y[i]
        return self.X[i]

class MalwareDetector(nn.Module):  # 原版逐字
    def __init__(self, input_size=512):
        super().__init__()
        self.img_size = int(np.sqrt(input_size))
        if self.img_size * self.img_size < input_size:
            self.img_size += 1
        self.conv_layers = nn.Sequential(
            nn.Conv2d(1, 60, kernel_size=2, stride=1, padding=1), nn.ReLU(), nn.MaxPool2d(2),
            nn.Conv2d(60, 200, kernel_size=2, stride=1, padding=1), nn.ReLU(), nn.MaxPool2d(2),
        )
        conv_output_size = self._get_conv_output_size()
        self.fc_layers = nn.Sequential(
            nn.Flatten(), nn.Linear(conv_output_size, 500), nn.ReLU(), nn.Linear(500, 1), nn.Sigmoid())
    def _get_conv_output_size(self):
        x = torch.randn(1, 1, self.img_size, self.img_size)
        return self.conv_layers(x).numel()
    def forward(self, x):
        bs, fs = x.size(0), x.size(1)
        if fs < self.img_size * self.img_size:
            pad = torch.zeros(bs, self.img_size * self.img_size - fs, device=x.device)
            x = torch.cat([x, pad], dim=1)
        else:
            x = x[:, :self.img_size * self.img_size]
        x = x.view(bs, 1, self.img_size, self.img_size)
        return self.fc_layers(self.conv_layers(x)).squeeze(1)

_cache = {}
def load_hist(h, dirs):
    for d in dirs:
        for name in (f'{h}.txt', f'VirusShare_{h}.txt', f'ransom_{h}.txt'):
            p = f'{d}/{name}'
            if p in _cache: return _cache[p]
            if os.path.exists(p):
                v = np.loadtxt(p, dtype=np.float32)
                if v.shape != (512,): continue
                _cache[p] = v
                return v
    return None

def metrics(y, p):
    return (accuracy_score(y, p), precision_score(y, p, zero_division=0),
            recall_score(y, p, zero_division=0), f1_score(y, p, zero_division=0))

def run(task, lab_csv, wild_csv, ben_dirs):
    print(f'===== {task} EHc v2 =====', flush=True)
    rows, feats, ys = [], [], []
    for c in [lab_csv, wild_csv]:
        pass
    def build(csv_path, tag):
        X, y, hs = [], [], []
        df = pd.read_csv(csv_path)
        for _, r in df.iterrows():
            h = str(r['hash']).strip().removesuffix('.exe')
            if not str(r['filename']).startswith('VirusShare'):
                continue
            v = load_hist(h, ben_dirs[0] if False else ben_dirs)
            if v is None: continue
            X.append(v); y.append(int(r['label'])); hs.append((h, tag))
        return X, y, hs
    # 恶意
    for name, c in [('lab', lab_csv), ('wild', wild_csv)]:
        pass
    # 简化: 直接读两个CSV合并再分
    lab_df = pd.read_csv(lab_csv); wild_df = pd.read_csv(wild_csv)
    def feats_from(df):
        X, y, ben_mask = [], [], []
        for _, r in df.iterrows():
            h = str(r['hash']).strip().removesuffix('.exe')
            v = load_hist(h, ben_dirs)
            if v is None: continue
            X.append(v); y.append(int(r['label'])); ben_mask.append(not str(r['filename']).startswith('VirusShare'))
        return np.array(X), np.array(y), np.array(ben_mask)
    XL, yL, bmL = feats_from(lab_df)
    XW, yW, bmW = feats_from(wild_df)
    print(f'Lab {len(XL)}(良{bmL.sum()}) Wild {len(XW)}(良{bmW.sum()})', flush=True)
    skf = StratifiedKFold(5, shuffle=True, random_state=SEED)
    wprobs = np.zeros(len(XW)); lms = []
    for f, (tr, te) in enumerate(skf.split(XL, yL), 1):
        model = MalwareDetector(512).to(DEV)
        opt = torch.optim.Adam(model.parameters(), lr=1e-3)
        lf = nn.BCELoss()
        tl = DataLoader(HistDS(XL[tr], yL[tr]), batch_size=32, shuffle=True)
        vl = DataLoader(HistDS(XL[te], yL[te]), batch_size=64)
        wl = DataLoader(HistDS(XW), batch_size=64)
        best, noimp = float('inf'), 0
        for ep in range(30):
            model.train()
            for x, y in tl:
                x, y = x.to(DEV), y.to(DEV)
                opt.zero_grad(); loss = lf(model(x), y); loss.backward(); opt.step()
            model.eval(); vl_loss = 0
            with torch.no_grad():
                for x, y in vl:
                    x, y = x.to(DEV), y.to(DEV)
                    vl_loss += lf(model(x), y).item() * x.size(0)
            vl_loss /= len(vl.dataset)
            if vl_loss < best: best, noimp = vl_loss, 0
            else:
                noimp += 1
                if noimp >= 7: break
        model.eval()
        def pred(loader):
            out = []
            with torch.no_grad():
                for batch in loader:
                    x = batch[0] if isinstance(batch, (list, tuple)) else batch
                    out.append(model(x.to(DEV)).cpu().numpy())
            return np.concatenate(out)
        pl = pred(vl); wprobs += pred(wl) / 5
        lms.append(metrics(yL[te], (pl >= 0.5).astype(int)))
        print(f'fold{f}: {tuple(round(x,4) for x in lms[-1])}', flush=True)
    pw = (wprobs >= 0.5).astype(int)
    lm = np.mean(lms, axis=0); wm = metrics(yW, pw)
    fpr = float(pw[bmW].mean()) if bmW.any() else -1
    print(f'\n===== {task} EHc v2 结果 =====')
    print(f'Lab(五折): ACC={lm[0]:.4f} PRE={lm[1]:.4f} REC={lm[2]:.4f} F1={lm[3]:.4f}')
    print(f'Wild:      ACC={wm[0]:.4f} PRE={wm[1]:.4f} REC={wm[2]:.4f} F1={wm[3]:.4f}')
    print(f'良性FPR={fpr:.4f} (n={int(bmW.sum())})')
    import json
    json.dump(dict(task=f'{task}EHc', lab=[round(x,4) for x in lm], wild=[round(x,4) for x in wm],
                   benign_fpr=round(fpr,4), n_lab=len(XL), n_wild=len(XW)),
              open(f'{W}/ehc_{task}_v2_results.json','w'), ensure_ascii=False)

if __name__ == '__main__':
    which = sys.argv[1] if len(sys.argv) > 1 else 'both'
    if which in ('miner', 'both'):
        run('挖矿', f'{LAB}/cryptojacking_lab_v2.csv', f'{LAB}/cryptojacking_wild_v2.csv',
            [f'{B}/hist_features/miner', f'{B}/hist_features/benign_miner'])
    if which in ('ransom', 'both'):
        run('勒索', f'{LAB}/ransomware_lab_v2.csv', f'{LAB}/ransomware_wild_v2.csv',
            [f'{B}/hist_features/ransom_pos', f'{B}/hist_features/ransom_neg', f'{B}/hist_features/benign_ransom'])
    print('EHC_V2_DONE')
