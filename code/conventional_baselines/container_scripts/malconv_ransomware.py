#!/usr/bin/env python3
"""MalConv 勒索任务(容器GPU): 恶意(wild_ransom_bin+wild_nonrw_bin) + 良性(~/v2_benign_in_r)
Lab: balanced_lab(6000恶意,其中正2000) + 良性1000; Wild: balanced_wild(15423) + 良性2000"""
import os, json, time, glob
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import Dataset, DataLoader
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

BASE = '/home/aapt/disk1.7T/aapt-u1_data'
LAB = os.path.expanduser('~/v2data/labels')
BENIGN_DIR = "/home/aapt/disk1.7T/aapt-u1_data/v2_benign_in_r"
SEED = 42
MAXLEN = 2_000_000
DEV = 'cuda' if torch.cuda.is_available() else 'cpu'
torch.manual_seed(SEED); np.random.seed(SEED)

def metrics(y, p):
    return (float(accuracy_score(y,p)), float(precision_score(y,p,zero_division=0)),
            float(recall_score(y,p,zero_division=0)), float(f1_score(y,p,zero_division=0)))

def index_malware():
    idx = {}
    for sub in ['wild_ransom_bin', 'wild_nonrw_bin']:
        for p in glob.glob(f'{BASE}/{sub}/**/VirusShare_*', recursive=True):
            fn = os.path.basename(p)
            if fn.startswith('VirusShare_'):
                idx[fn.replace('VirusShare_','')] = p
    return idx

def bytes_to_tensor(path):
    with open(path,'rb') as f:
        b = f.read(MAXLEN)
    a = np.frombuffer(b, dtype=np.uint8).astype(np.int64)[:MAXLEN]
    t = np.zeros(MAXLEN, dtype=np.int64)
    t[:len(a)] = a + 1
    return t

class PEDataset(Dataset):
    def __init__(self, items): self.items = items
    def __len__(self): return len(self.items)
    def __getitem__(self, i):
        p, y = self.items[i]
        return torch.from_numpy(bytes_to_tensor(p)), y

class MalConv(nn.Module):
    def __init__(self):
        super().__init__()
        self.embed = nn.Embedding(257, 8, padding_idx=0)
        self.conv1 = nn.Conv1d(8, 128, 500, stride=500)
        self.conv2 = nn.Conv1d(8, 128, 500, stride=500)
        self.fc = nn.Linear(128, 1)
    def forward(self, x):
        e = self.embed(x).transpose(1,2)
        h = self.conv1(e) * torch.sigmoid(self.conv2(e))
        h = F.max_pool1d(h, h.size(2)).squeeze(2)
        return self.fc(h).squeeze(1)

def infer(model, loader):
    model.eval(); outs = []
    with torch.no_grad():
        for xb, _ in loader:
            outs.append(torch.sigmoid(model(xb.to(DEV))).cpu().numpy())
    return np.concatenate(outs)

def main():
    print('===== 勒索 MalConv =====', flush=True)
    mal = index_malware()
    print(f'恶意索引: {len(mal)}', flush=True)
    lab = pd.read_csv(f'{LAB}/balanced_lab_dataset_1to2.csv')
    wild = pd.read_csv(f'{LAB}/balanced_wild_dataset_1to2.csv')
    v2l = pd.read_csv(f'{LAB}/ransomware_lab.csv')
    v2w = pd.read_csv(f'{LAB}/ransomware_wild.csv')

    def build(df, benign_hashes):
        items = []
        for h, y in zip(df['hash'].astype(str), df['label']):
            if h in mal: items.append((mal[h], int(y)))
        for h in benign_hashes:
            p = f'{BENIGN_DIR}/{h}.exe'
            if os.path.exists(p): items.append((p, 0))
        return items

    bl = [h for h in v2l[v2l['source']=='benign']['hash']]
    bw = [h for h in v2w[v2w['source']=='benign']['hash']]
    lab_items = build(lab, bl); wild_items = build(wild, bw)
    print(f'lab={len(lab_items)} wild={len(wild_items)} (良性lab={sum(1 for h in bl if os.path.exists(f"{BENIGN_DIR}/{h}.exe"))}, wild={sum(1 for h in bw if os.path.exists(f"{BENIGN_DIR}/{h}.exe"))})', flush=True)

    yl = np.array([y for _,y in lab_items])
    skf = StratifiedKFold(5, shuffle=True, random_state=SEED)
    wild_probs = np.zeros(len(wild_items)); lab_scores = []
    for f, (tr, te) in enumerate(skf.split(np.zeros(len(yl)), yl), 1):
        model = MalConv().to(DEV)
        opt = torch.optim.Adam(model.parameters(), lr=1e-3)
        pos_w = torch.tensor([(len(tr)-yl[tr].sum())/max(yl[tr].sum(),1)], dtype=torch.float32).to(DEV)
        lf = nn.BCEWithLogitsLoss(pos_weight=pos_w)
        tr_loader = DataLoader(PEDataset([(lab_items[i][0], yl[i]) for i in tr]), batch_size=4, shuffle=True, num_workers=8)
        te_loader = DataLoader(PEDataset([lab_items[i] for i in te]), batch_size=8, num_workers=4)
        wl_loader = DataLoader(PEDataset(wild_items), batch_size=8, num_workers=4)
        model.train()
        for ep in range(5):
            t0=time.time()
            for xb, yb in tr_loader:
                xb, yb = xb.to(DEV), yb.float().to(DEV)
                opt.zero_grad(); loss = lf(model(xb), yb); loss.backward(); opt.step()
            print(f'  fold{f} ep{ep} loss={loss.item():.4f} ({time.time()-t0:.0f}s)', flush=True)
        pl = infer(model, te_loader); wild_probs += infer(model, wl_loader)/5
        lab_scores.append(metrics(yl[te], (pl>0.5).astype(int)))

    pw = (wild_probs>0.5).astype(int)
    yw = np.array([y for _,y in wild_items])
    n_ben = sum(1 for h in bw if os.path.exists(f'{BENIGN_DIR}/{h}.exe'))
    bm = np.concatenate([np.zeros(len(wild_items)-n_ben, bool), np.ones(n_ben, bool)])
    lm = np.mean(lab_scores, axis=0); wm = metrics(yw, pw)
    fpr = float((pw[bm]==1).mean())
    res = dict(task='勒索', lab=[round(x,4) for x in lm], wild=[round(x,4) for x in wm], benign_fpr=round(fpr,4),
               n_lab=len(lab_items), n_wild=len(wild_items))
    print(json.dumps(res, ensure_ascii=False), flush=True)
    with open(os.path.expanduser('~/malconv_v2_results.json'),'a') as f:
        f.write(json.dumps(res, ensure_ascii=False)+'\n')
    pd.DataFrame({'path':[p for p,_ in wild_items], 'label':yw, 'prob':wild_probs}).to_csv(
        os.path.expanduser('~/malconv_勒索_wild_probs.csv'), index=False)

if __name__ == '__main__':
    main()
