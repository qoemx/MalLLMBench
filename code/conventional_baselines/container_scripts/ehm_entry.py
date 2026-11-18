#!/usr/bin/env python3
"""容器统一补存: 所有分类器的五折权重 + Wild逐样本置信度
每组用与原实验完全同款的模型与协议, 重训一遍(权重丢了只能重训)
顺序: EHm挖矿(MLP) → EHc×2(CNN) → GI×2(CNN) → RB×2(MalConv)
产出: ./container_workspace/artifacts/{name}/models + confidence"""
import os, sys, time, json, glob
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader, TensorDataset
from sklearn.model_selection import StratifiedKFold
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import joblib

B = "/home/aapt/disk1.7T/aapt-u1_data"
LAB = "./data/manifests"
OUT = f"{B}/work/artifacts"
DEV = 'cuda' if torch.cuda.is_available() else 'cpu'
SEED = 42
torch.manual_seed(SEED); np.random.seed(SEED)
os.makedirs(OUT, exist_ok=True)

def metrics(y, p):
    return (accuracy_score(y, p), precision_score(y, p, zero_division=0),
            recall_score(y, p, zero_division=0), f1_score(y, p, zero_division=0))

# ---------- EH 直方图加载(512维txt) ----------
_hist_cache = {}
def load_hist(h, dirs):
    for d in dirs:
        for name in (f"{h}.txt", f"VirusShare_{h}.txt", f"ransom_{h}.txt"):
            p = f"{d}/{name}"
            if p in _hist_cache: return _hist_cache[p]
            if os.path.exists(p):
                v = np.loadtxt(p, dtype=np.float32)
                if v.shape != (512,): continue
                _hist_cache[p] = v
                return v
    return None

def build_hist_task(lab_csv, wild_csv, dirs):
    def feats(df):
        X, y, fn, bm = [], [], [], []
        for _, r in df.iterrows():
            h = str(r['hash']).strip().removesuffix('.exe')
            v = load_hist(h, dirs)
            if v is None: continue
            X.append(v); y.append(int(r['label'])); fn.append(h)
            bm.append(r.get('source', 'malware') == 'benign')
        return np.array(X), np.array(y), fn, np.array(bm)
    XL, yL, fnL, bmL = feats(pd.read_csv(lab_csv))
    XW, yW, fnW, bmW = feats(pd.read_csv(wild_csv))
    return XL, yL, XW, yW, fnW, bmW

# ---------- EHc CNN (原版) ----------
class EHC_CNN(nn.Module):
    def __init__(self, input_size=512):
        super().__init__()
        self.img_size = int(np.sqrt(input_size))
        if self.img_size ** 2 < input_size: self.img_size += 1
        self.conv = nn.Sequential(
            nn.Conv2d(1, 60, 2, 1, 1), nn.ReLU(), nn.MaxPool2d(2),
            nn.Conv2d(60, 200, 2, 1, 1), nn.ReLU(), nn.MaxPool2d(2))
        cs = self.conv(torch.randn(1, 1, self.img_size, self.img_size)).numel()
        self.fc = nn.Sequential(nn.Flatten(), nn.Linear(cs, 500), nn.ReLU(), nn.Linear(500, 1), nn.Sigmoid())
    def forward(self, x):
        bs = x.size(0)
        if x.size(1) < self.img_size**2:
            pad = torch.zeros(bs, self.img_size**2 - x.size(1), device=x.device)
            x = torch.cat([x, pad], 1)
        else: x = x[:, :self.img_size**2]
        return self.fc(self.conv(x.view(bs, 1, self.img_size, self.img_size))).squeeze(1)

# ---------- GI CNN (run_v2_gpu.py 同款: 2conv) ----------
class GI_CNN(nn.Module):
    """run_v2_gpu.py 原版 GICNN 逐字复刻"""
    def __init__(self):
        super().__init__()
        self.net = nn.Sequential(
            nn.Conv2d(1, 32, 3, padding=1), nn.BatchNorm2d(32), nn.ReLU(), nn.MaxPool2d(2),
            nn.Conv2d(32, 64, 3, padding=1), nn.BatchNorm2d(64), nn.ReLU(), nn.MaxPool2d(2),
            nn.Conv2d(64, 128, 3, padding=1), nn.BatchNorm2d(128), nn.ReLU(), nn.MaxPool2d(2),
            nn.Conv2d(128, 128, 3, padding=1), nn.BatchNorm2d(128), nn.ReLU(), nn.AdaptiveAvgPool2d(1),
            nn.Flatten(), nn.Linear(128, 2))
    def forward(self, x):
        return self.net(x)

# ---------- MalConv (原版) ----------
class MalConv(nn.Module):
    def __init__(self):
        super().__init__()
        self.emb = nn.Embedding(257, 8, padding_idx=0)
        self.c1 = nn.Conv1d(8, 128, 500, 500)
        self.c2 = nn.Conv1d(8, 128, 500, 500)
        self.fc = nn.Linear(128, 1)
    def forward(self, x):
        e = self.emb(x).transpose(1, 2)
        h = self.c1(e) * torch.sigmoid(self.c2(e))
        return self.fc(h.max(2).values).squeeze(1)

class BinDS(Dataset):
    def __init__(self, files, labels=None, size=2000000):
        self.files = files; self.labels = labels; self.size = size
    def __len__(self): return len(self.files)
    def __getitem__(self, i):
        with open(self.files[i], 'rb') as f: b = f.read(self.size)
        x = np.zeros(self.size, dtype=np.int64)
        x[:len(b)] = np.frombuffer(b, dtype=np.uint8).astype(np.int64) + 1
        if self.labels is not None:
            return torch.from_numpy(x), float(self.labels[i])
        return torch.from_numpy(x)

def run_conf(name, XL, yL, XW, yW, fnW, bmW, train_fn):
    """train_fn(Xtr, yTr, fold) -> model; model需要 predict_proba(X)->np 或 torch"""
    d = f"{OUT}/{name}"
    os.makedirs(f"{d}/models", exist_ok=True); os.makedirs(f"{d}/confidence", exist_ok=True)
    skf = StratifiedKFold(5, shuffle=True, random_state=SEED)
    wprobs = np.zeros(len(XW)); lms = []
    for f, (tr, te) in enumerate(skf.split(XL, yL), 1):
        t0 = time.time()
        mdl = train_fn(XL, yL, tr, f)
        # 保存权重
        if hasattr(mdl, 'state_dict'):
            torch.save(mdl.state_dict(), f"{d}/models/fold{f}.pth")
        else:
            joblib.dump(mdl, f"{d}/models/fold{f}.joblib")
        # wild概率
        if hasattr(mdl, 'predict_proba'):
            wp = mdl.predict_proba(XW)[:, 1]
        else:
            mdl.eval()
            out = mdl(torch.tensor(np.array(XW), dtype=torch.float32).unsqueeze(1).to(DEV)).detach()
            wp = torch.softmax(out, 1)[:, 1].cpu().numpy() if out.dim() == 2 and out.size(1) == 2 else torch.sigmoid(out.squeeze(1)).cpu().numpy()
        wprobs += wp / 5
        lms.append((f, time.time()-t0))
        print(f"[{name}] fold{f} done ({time.time()-t0:.0f}s)", flush=True)
    pred = (wprobs >= 0.5).astype(int)
    pd.DataFrame({"filename": fnW, "label": yW, "prob": wprobs, "pred": pred, "is_benign": bmW}
                 ).to_csv(f"{d}/confidence/wild_v2_confidence.csv", index=False)
    wm = metrics(yW, pred)
    fpr = float(pred[bmW].mean()) if bmW.any() else -1
    print(f"[{name}] Wild ACC={wm[0]:.4f} F1={wm[3]:.4f} 良性FPR={fpr:.4f}", flush=True)
    json.dump(dict(name=name, wild=[round(x,4) for x in wm], benign_fpr=round(fpr,4)),
              open(f"{d}/results.json", "w"))

if __name__ == "__main__":
    which = sys.argv[1]
    if which == "eh_miner":
        XL, yL, XW, yW, fnW, bmW = build_hist_task(
            f"{LAB}/cryptojacking_lab_v2.csv", f"{LAB}/cryptojacking_wild_v2.csv",
            [f"{B}/hist_features/miner", f"{B}/hist_features/benign_miner"])
        print(f"Lab {len(XL)} Wild {len(XW)}", flush=True)
        def tr(XL, yL, tr_idx, f):
            clf = MLPClassifier(hidden_layer_sizes=(128, 64), max_iter=300, random_state=SEED)
            clf.fit(XL[tr_idx], yL[tr_idx])
            return clf
        run_conf("crypto_EHm", XL, yL, XW, yW, fnW, bmW, tr)
    elif which == "ehc_miner":
        XL, yL, XW, yW, fnW, bmW = build_hist_task(
            f"{LAB}/cryptojacking_lab_v2.csv", f"{LAB}/cryptojacking_wild_v2.csv",
            [f"{B}/hist_features/miner", f"{B}/hist_features/benign_miner"])
        print(f"Lab {len(XL)} Wild {len(XW)}", flush=True)
        class _DS(torch.utils.data.Dataset):
            def __init__(s, X, y): s.X = torch.tensor(X, dtype=torch.float32); s.y = torch.tensor(y, dtype=torch.float32)
            def __len__(s): return len(s.y)
            def __getitem__(s, i): return s.X[i], s.y[i]
        def tr(XL, yL, tr_idx, f):
            m = EHC_CNN(512).to(DEV)
            opt = torch.optim.Adam(m.parameters(), lr=1e-3); lf = nn.BCELoss()
            g = torch.Generator().manual_seed(SEED)
            dl = DataLoader(_DS(XL[tr_idx], yL[tr_idx]), batch_size=32, shuffle=True, generator=g)
            best, noimp, state = float('inf'), 0, None
            for ep in range(30):
                m.train()
                for x, y in dl:
                    x, y = x.to(DEV), y.to(DEV)
                    opt.zero_grad(); lf(m(x), y).backward(); opt.step()
                m.eval()
                with torch.no_grad():
                    vl = sum(lf(m(xb.to(DEV)), yb.to(DEV)).item()*len(xb) for xb, yb in
                             DataLoader(_DS(XL[tr_idx], yL[tr_idx]), batch_size=256)) / len(tr_idx)
                if vl < best: best, noimp, state = vl, 0, m.state_dict()
                else:
                    noimp += 1
                    if noimp >= 7: break
            m.load_state_dict(state)
            return m
        run_conf("crypto_EHc", XL, yL, XW, yW, fnW, bmW, tr)
    elif which == "ehc_ransom":
        XL, yL, XW, yW, fnW, bmW = build_hist_task(
            f"{LAB}/ransomware_lab_v2.csv", f"{LAB}/ransomware_wild_v2.csv",
            [f"{B}/hist_features/ransom_pos", f"{B}/hist_features/ransom_neg", f"{B}/hist_features/benign_ransom"])
        print(f"Lab {len(XL)} Wild {len(XW)}", flush=True)
        class _DS(torch.utils.data.Dataset):
            def __init__(s, X, y): s.X = torch.tensor(X, dtype=torch.float32); s.y = torch.tensor(y, dtype=torch.float32)
            def __len__(s): return len(s.y)
            def __getitem__(s, i): return s.X[i], s.y[i]
        def tr(XL, yL, tr_idx, f):
            m = EHC_CNN(512).to(DEV)
            opt = torch.optim.Adam(m.parameters(), lr=1e-3); lf = nn.BCELoss()
            g = torch.Generator().manual_seed(SEED)
            dl = DataLoader(_DS(XL[tr_idx], yL[tr_idx]), batch_size=32, shuffle=True, generator=g)
            best, noimp, state = float('inf'), 0, None
            for ep in range(30):
                m.train()
                for x, y in dl:
                    x, y = x.to(DEV), y.to(DEV)
                    opt.zero_grad(); lf(m(x), y).backward(); opt.step()
                m.eval()
                with torch.no_grad():
                    vl = sum(lf(m(xb.to(DEV)), yb.to(DEV)).item()*len(xb) for xb, yb in
                             DataLoader(_DS(XL[tr_idx], yL[tr_idx]), batch_size=256)) / len(tr_idx)
                if vl < best: best, noimp, state = vl, 0, m.state_dict()
                else:
                    noimp += 1
                    if noimp >= 7: break
            m.load_state_dict(state)
            return m
        run_conf("ransom_EHc", XL, yL, XW, yW, fnW, bmW, tr)
    elif which in ("rb_miner", "rb_ransom"):
        # MalConv: 文件级, 每折5epoch batch4(与原实验同款)
        import glob as _g
        if which == "rb_miner":
            bin_mal = f"{B}/miner_task_bin/挖矿"; ben_dir = "/home/aapt-u1/v2_benign_in"
            lc, wc = f"{LAB}/cryptojacking_lab_v2.csv", f"{LAB}/cryptojacking_wild_v2.csv"
            name = "crypto_RB"
        else:
            bin_mal = None; ben_dir = f"{B}/v2_benign_in_r"
            lc, wc = f"{LAB}/ransomware_lab_v2.csv", f"{LAB}/ransomware_wild_v2.csv"
            name = "ransom_RB"
        def collect(df):
            files, ys, fns, bm_ = [], [], [], []
            for _, r in df.iterrows():
                if r.get('source', 'malware') == 'benign':
                    p = f"{ben_dir}/{r['hash']}"
                    if r['hash'].endswith('.exe'): p = f"{ben_dir}/{r['hash']}"
                    if os.path.exists(p): files.append(p); ys.append(0); fns.append(str(r['hash'])[:32]); bm_.append(True)
                else:
                    h = str(r['hash']).strip().removesuffix('.exe')
                    if bin_mal:
                        cands = [f"{B}/miner_task_bin/挖矿/VirusShare_{h}", f"{B}/miner_task_bin/挖矿白样本/VirusShare_{h}"]
                    else:
                        cands = [f"{B}/wild_ransom_bin/VirusShare_{h}", f"{B}/wild_nonrw_bin/VirusShare_{h}"]
                    for c in cands:
                        if os.path.exists(c):
                            files.append(c); ys.append(int(r['label'])); fns.append(h); bm_.append(False); break
            return files, np.array(ys), fns, np.array(bm_)
        lf_, wl_ = pd.read_csv(lc), pd.read_csv(wc)
        FL, yL, _, _ = collect(lf_)
        FW, yW, fnW, bmW = collect(wl_)
        print(f"Lab {len(FL)} Wild {len(FW)}", flush=True)
        skf = StratifiedKFold(5, shuffle=True, random_state=SEED)
        wprobs = np.zeros(len(FW)); lms = []
        d_ = f"{OUT}/{name}"; os.makedirs(f"{d_}/models", exist_ok=True); os.makedirs(f"{d_}/confidence", exist_ok=True)
        for f_, (tr, te) in enumerate(skf.split(np.zeros(len(FL)), yL), 1):
            t0 = time.time()
            m = MalConv().to(DEV)
            pw = torch.tensor(np.bincount(yL[tr])[0] / max(np.bincount(yL[tr])[1],1), dtype=torch.float32).to(DEV)
            lf2 = nn.BCEWithLogitsLoss(pos_weight=pw)
            opt = torch.optim.Adam(m.parameters(), lr=1e-3)
            tl = DataLoader(BinDS([FL[i] for i in tr], yL[tr]), batch_size=4, shuffle=True)
            m.train()
            for ep in range(5):
                for x, y in tl:
                    x, y = x.to(DEV), y.to(DEV)
                    opt.zero_grad(); lf2(m(x), y).backward(); opt.step()
            torch.save(m.state_dict(), f"{d_}/models/fold{f_}.pth")
            m.eval()
            wl = DataLoader(BinDS(FW), batch_size=8)
            ps = []
            with torch.no_grad():
                for x in wl:
                    ps.extend(torch.sigmoid(m(x.to(DEV))).cpu().numpy())
            wprobs += np.array(ps) / 5
            print(f"[{name}] fold{f_} done ({time.time()-t0:.0f}s)", flush=True)
        pred = (wprobs >= .5).astype(int)
        pd.DataFrame({"filename": fnW, "label": yW, "prob": wprobs, "pred": pred, "is_benign": bmW}
                     ).to_csv(f"{d_}/confidence/wild_v2_confidence.csv", index=False)
        wm = metrics(yW, pred); fpr = float(pred[bmW].mean())
        print(f"[{name}] Wild ACC={wm[0]:.4f} F1={wm[3]:.4f} 良性FPR={fpr:.4f}", flush=True)
        json.dump(dict(name=name, wild=[round(x,4) for x in wm], benign_fpr=round(fpr,4)), open(f"{d_}/results.json","w"))
    elif which in ("gi_miner", "gi_ransom"):
        # GI: 恶意npz(miner_features / ransom_features/shard0) + 良性benign_gi_features.npz
        import glob as _g
        def load_npz_feat(dirs):
            m = {}
            for d in dirs:
                for fp in _g.glob(f"{d}/*.npz"):
                    h = os.path.basename(fp).replace(".npz", "")
                    try:
                        z = np.load(fp)
                        v = z[list(z.keys())[0]].reshape(-1)
                        if len(v) >= 65: m[h] = v
                    except Exception: pass
            return m
        if which == "gi_miner":
            mal_map = load_npz_feat(["/home/aapt-u1/miner_features"])
            name = "crypto_GI"
        else:
            mal_map = load_npz_feat(["/home/aapt-u1/ransom_features/shard0"])
            name = "ransom_GI"
        ben_z = np.load("/home/aapt-u1/v2data/benign_gi_features.npz", allow_pickle=True)
        ben_map = {str(h): v for h, v in zip(ben_z["hashes"], ben_z["features"])}
        def collect(df):
            X, y, fn, bm_ = [], [], [], []
            for _, r in df.iterrows():
                h = str(r['hash']).strip().removesuffix('.exe')
                if r.get('source', 'malware') == 'benign':
                    if h in ben_map:
                        X.append(np.asarray(ben_map[h], dtype=np.float32).reshape(163,65)); y.append(0); fn.append(h); bm_.append(True)
                else:
                    if h in mal_map:
                        X.append(np.asarray(mal_map[h], dtype=np.float32).reshape(163,65)); y.append(int(r['label'])); fn.append(h); bm_.append(False)
            return np.array(X, dtype=np.float32), np.array(y), fn, np.array(bm_)
        lc = f"{LAB}/cryptojacking_lab_v2.csv" if which == "gi_miner" else f"{LAB}/ransomware_lab_v2.csv"
        wc = f"{LAB}/cryptojacking_wild_v2.csv" if which == "gi_miner" else f"{LAB}/ransomware_wild_v2.csv"
        XL, yL, _, _ = collect(pd.read_csv(lc))
        XW, yW, fnW, bmW = collect(pd.read_csv(wc))
        print(f"Lab {len(XL)} Wild {len(XW)}", flush=True)
        class _GDS(torch.utils.data.Dataset):
            def __init__(s, X, y): s.X = torch.tensor(X, dtype=torch.float32); s.y = torch.tensor(y, dtype=torch.float32)
            def __len__(s): return len(s.y)
            def __getitem__(s, i): return s.X[i], s.y[i]
        # 原版gi_train逐字复刻(带保存): 不经run_conf, 直接内联
        import copy
        OUTD = f"{OUT}/{name}"
        os.makedirs(f"{OUTD}/models", exist_ok=True); os.makedirs(f"{OUTD}/confidence", exist_ok=True)
        XL_ = np.array(XL, dtype=np.float32).reshape(-1,1,163,65)
        XW_ = np.array(XW, dtype=np.float32).reshape(-1,1,163,65)
        skf = StratifiedKFold(5, shuffle=True, random_state=42)
        wp = np.zeros(len(XW_)); lms = []
        for f, (tr, te) in enumerate(skf.split(XL_, yL), 1):
            torch.manual_seed(42)
            m = GI_CNN().to(DEV)
            opt = torch.optim.Adam(m.parameters(), lr=1e-3, weight_decay=1e-4)
            sch = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=30)
            lf = nn.CrossEntropyLoss()
            loader = DataLoader(TensorDataset(torch.tensor(XL_[tr]), torch.tensor(yL[tr]).long()),
                                batch_size=128, shuffle=True, num_workers=2)
            m.train()
            for ep in range(30):
                for xb, yb in loader:
                    xb, yb = xb.to(DEV), yb.to(DEV)
                    opt.zero_grad(); lf(m(xb), yb).backward(); opt.step()
                sch.step()
            torch.save(m.state_dict(), f"{OUTD}/models/fold{f}.pth")
            m.eval()
            with torch.no_grad():
                def _pred(X):
                    outs = []
                    for i in range(0, len(X), 512):
                        outs.append(m(torch.tensor(X[i:i+512]).to(DEV)).softmax(1)[:,1].cpu().numpy())
                    return np.concatenate(outs)
                pl = _pred(XL_[te]); wp += _pred(XW_)/5
            lms.append(metrics(yL[te], (pl>0.5).astype(int)))
            print(f"[{name}] fold{f}: {tuple(round(x,4) for x in lms[-1])}", flush=True)
        pw = (wp>0.5).astype(int)
        bm_arr = np.array(bmW)
        pd.DataFrame({"filename": fnW, "label": yW, "prob": wp, "pred": pw, "is_benign": bm_arr}
                     ).to_csv(f"{OUTD}/confidence/wild_v2_confidence.csv", index=False)
        lm = np.mean(lms, axis=0); wm = metrics(yW, pw)
        fpr = float(pw[bm_arr].mean()) if bm_arr.any() else -1
        print(f"[{name}] Lab F1={lm[3]:.4f} Wild ACC={wm[0]:.4f} F1={wm[3]:.4f} 良性FPR={fpr:.4f}", flush=True)
        json.dump(dict(name=name, lab=[round(x,4) for x in lm], wild=[round(x,4) for x in wm], benign_fpr=round(fpr,4)),
                  open(f"{OUTD}/results.json","w"))
        # (原tr/run_conf路径不再走)
        run_conf(name, XL, yL, XW, yW, fnW, bmW, tr)

