#!/usr/bin/env python3
"""挖矿 CFG-GIN v2 (统一GDL解析器版)
GDL -> 图(节点23维) -> 4层GIN -> 5折 -> Wild"""
import os, sys, time, glob
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gdl_parser import parse_gdl
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.data import Data
from torch_geometric.nn import GINConv, global_max_pool
from torch_geometric.loader import DataLoader as PyGLoader
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

B = '/home/aapt/disk1.7T/aapt-u1_data'
LAB = './data/manifests'
DEV = 'cuda' if torch.cuda.is_available() else 'cpu'
SEED = 42
torch.manual_seed(SEED); np.random.seed(SEED)

def load_dir(d, strip=''):
    out = {}
    for p in glob.glob(f'{d}/*_cfg.gdl'):
        h = os.path.basename(p)[:-len('_cfg.gdl')].replace(strip, '').replace('.exe', '')
        r = parse_gdl(p)
        if r is None: continue
        x, ei = r
        out[h] = (Data(x=torch.tensor(x), edge_index=torch.tensor(ei)), None)  # y由build时注入
    return out

def metrics(y, p):
    return (float(accuracy_score(y, p)), float(precision_score(y, p, zero_division=0)),
            float(recall_score(y, p, zero_division=0)), float(f1_score(y, p, zero_division=0)))

class GIN(nn.Module):
    def __init__(self, in_ch=23):
        super().__init__()
        chans = [32, 64, 48, 24]
        self.convs = nn.ModuleList()
        for k in range(4):
            d = chans[k]
            mlp = nn.Sequential(nn.Linear(in_ch if k == 0 else chans[k-1], d), nn.ReLU(), nn.Linear(d, d))
            self.convs.append(GINConv(mlp))
        self.fc1 = nn.Linear(chans[-1], 32); self.bn1 = nn.BatchNorm1d(32)
        self.fc2 = nn.Linear(32, 2); self.dropout = nn.Dropout(0.3)
    def forward(self, x, ei, batch):
        for conv in self.convs:
            x = conv(x, ei); x = F.relu(x); x = self.dropout(x)
        x = global_max_pool(x, batch)
        x = F.relu(self.bn1(self.fc1(x)))
        return self.fc2(self.dropout(x))

def run(task, mal_dir, mal_strip, lab_csv, wild_csv, v2l_csv, v2w_csv, ben_dir):
    print(f'===== {task} CFG-GIN v2 =====', flush=True)
    t0 = time.time()
    mal = load_dir(mal_dir, mal_strip)
    print(f'恶意图: {len(mal)} ({time.time()-t0:.0f}s)', flush=True)
    ben = load_dir(ben_dir)
    print(f'良性图: {len(ben)}', flush=True)
    lab = pd.read_csv(lab_csv); wild = pd.read_csv(wild_csv)
    v2l = pd.read_csv(v2l_csv); v2w = pd.read_csv(v2w_csv)

    def build(df, bh):
        gs, ys = [], []
        for h, l in zip(df['hash'].astype(str), df['label']):
            if h in mal:
                g, _ = mal[h]
                g.y = torch.tensor([int(l)], dtype=torch.long)
                gs.append(g); ys.append(l)
        nb = 0
        for h in bh:
            if h in ben:
                g, _ = ben[h]
                g.y = torch.tensor([0], dtype=torch.long)
                gs.append(g); ys.append(0); nb += 1
        return gs, np.array(ys), nb

    Lg, Ly, Lnb = build(lab, v2l[v2l['source'] == 'benign'].hash)
    Wg, Wy, Wnb = build(wild, v2w[v2w['source'] == 'benign'].hash)
    print(f'Lab {len(Lg)}(良{Lnb}) | Wild {len(Wg)}(良{Wnb})', flush=True)

    skf = StratifiedKFold(5, shuffle=True, random_state=SEED)
    wprobs = np.zeros(len(Wg)); lms = []
    for f, (tr, te) in enumerate(skf.split(np.zeros(len(Ly)), Ly), 1):
        model = GIN().to(DEV)
        opt = torch.optim.Adam(model.parameters(), lr=1e-3, weight_decay=1e-4)
        lf = nn.CrossEntropyLoss()
        tl = PyGLoader([Lg[i] for i in tr], batch_size=32, shuffle=True)
        vl = PyGLoader([Lg[i] for i in te], batch_size=64)
        wl = PyGLoader(Wg, batch_size=64)
        for ep in range(15):
            model.train()
            for b in tl:
                b = b.to(DEV)
                opt.zero_grad(); lf(model(b.x, b.edge_index, b.batch), b.y).backward(); opt.step()
        model.eval()
        def pred(loader):
            out = []
            with torch.no_grad():
                for b in loader:
                    b = b.to(DEV)
                    out.append(model(b.x, b.edge_index, b.batch).softmax(1)[:, 1].cpu().numpy())
            return np.concatenate(out)
        pl = pred(vl); wprobs += pred(wl) / 5
        lms.append(metrics(Ly[te], (pl > 0.5).astype(int)))
        print(f'fold{f}: {tuple(round(x, 4) for x in lms[-1])}', flush=True)

    pw = (wprobs > 0.5).astype(int)
    lm = np.mean(lms, axis=0); wm = metrics(Wy, pw)
    fpr = float((pw[-Wnb:] == 1).mean())
    print(f'\n===== {task} CFG-GIN v2 结果 =====')
    print(f'Lab(五折): ACC={lm[0]:.4f} PRE={lm[1]:.4f} REC={lm[2]:.4f} F1={lm[3]:.4f}')
    print(f'Wild:      ACC={wm[0]:.4f} PRE={wm[1]:.4f} REC={wm[2]:.4f} F1={wm[3]:.4f}')
    print(f'良性FPR={fpr:.4f}')
    import json
    with open(f'./container_workspace/cfg_gin_{task}_results.json', 'w') as fp:
        json.dump(dict(task=f'{task}CFG-GIN', lab=[round(x, 4) for x in lm], wild=[round(x, 4) for x in wm],
                       benign_fpr=round(fpr, 4), n_lab=len(Lg), n_wild=len(Wg)), fp, ensure_ascii=False)

if __name__ == '__main__':
    run('挖矿', f'{B}/miner_cfg/gdl_out', 'VirusShare_',
        f'{LAB}/lab_label.csv', f'{LAB}/wild_label.csv',
        f'{LAB}/cryptojacking_lab_v2.csv', f'{LAB}/cryptojacking_wild_v2.csv',
        f'{B}/benign_gdl_out')
