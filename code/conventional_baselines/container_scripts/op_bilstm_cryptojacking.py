#!/usr/bin/env python3
"""挖矿 OP-BiLSTM v2 —— 原版 train_improved.py 架构逐行复刻
(ImprovedTextCNN_LSTM + FocalLoss + AdamW + warmup/cosine + patience15 + thr0.5)
差异仅: ①输入=op_lab_v2.csv(恶意6000沿用原fold + 良性915追加) ②Wild=op_wild_v2.csv五折均值推理"""
import os, glob, pickle, time
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
from collections import Counter
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

W = "./container_workspace"
SPLIT = "./container_workspace/split_v2"
MAXLEN = 1024
EMBEDDING_DIM = 256
BATCH_SIZE = 12
EPOCHS = 100
PATIENCE = 15
LEARNING_RATE = 1e-3
WARMUP_EPOCHS = 5
DEVICE = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
SEED = 42
torch.manual_seed(SEED); np.random.seed(SEED)

class OpcodeDataset(Dataset):
    def __init__(self, df, vocab=None, maxlen=MAXLEN):
        self.labels = df['label'].astype(int).tolist()
        self.seqs = [str(s).split() for s in df['opcode_seq']]
        self.maxlen = maxlen
        if vocab is None:
            all_ops = [op for seq in self.seqs for op in seq]
            counter = Counter(all_ops)
            self.vocab = {op: i+2 for i, (op, _) in enumerate(counter.most_common())}
            self.vocab['<PAD>'] = 0; self.vocab['<UNK>'] = 1
        else:
            self.vocab = vocab
    def __len__(self): return len(self.labels)
    def __getitem__(self, idx):
        seq = self.seqs[idx]
        ids = [self.vocab.get(op, self.vocab['<UNK>']) for op in seq]
        if len(ids) < self.maxlen: ids += [self.vocab['<PAD>']] * (self.maxlen - len(ids))
        else: ids = ids[:self.maxlen]
        return torch.tensor(ids, dtype=torch.long), torch.tensor(self.labels[idx], dtype=torch.float)

class AttentionLayer(nn.Module):
    def __init__(self, hidden_dim):
        super().__init__()
        self.attention = nn.Sequential(nn.Linear(hidden_dim, hidden_dim), nn.Tanh(), nn.Linear(hidden_dim, 1))
    def forward(self, lstm_output):
        aw = torch.softmax(self.attention(lstm_output), dim=1)
        return torch.sum(aw * lstm_output, dim=1), aw

class ImprovedTextCNN_LSTM(nn.Module):
    def __init__(self, vocab_size, embedding_dim, maxlen):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embedding_dim, padding_idx=0)
        self.dropout_emb = nn.Dropout(0.3)
        self.conv_layers = nn.ModuleList([nn.Conv1d(embedding_dim, 256, kernel_size=k, padding=k//2) for k in [3,5,7,10]])
        self.dropout_convs = nn.ModuleList([nn.Dropout(0.3) for _ in range(4)])
        self.pool = nn.AdaptiveMaxPool1d(256)
        self.lstm = nn.LSTM(256*4, 512, batch_first=True, bidirectional=True, dropout=0.3, num_layers=2)
        self.attention = AttentionLayer(1024)
        self.layernorm = nn.LayerNorm(1024)
        self.fc1 = nn.Linear(1024, 512); self.dropout_fc1 = nn.Dropout(0.5)
        self.fc2 = nn.Linear(512, 256); self.dropout_fc2 = nn.Dropout(0.5)
        self.fc3 = nn.Linear(256, 1); self.relu = nn.ReLU()
    def forward(self, x):
        x = self.embedding(x); x = self.dropout_emb(x)
        x_conv = x.transpose(1, 2)
        conv_outputs = []
        for conv, dropout in zip(self.conv_layers, self.dropout_convs):
            c = self.relu(conv(x_conv)); c = dropout(c); c = self.pool(c)
            conv_outputs.append(c)
        x = torch.cat(conv_outputs, dim=1).transpose(1, 2)
        lstm_out, _ = self.lstm(x)
        x, _ = self.attention(lstm_out)
        x = self.layernorm(x)
        x = self.dropout_fc1(self.relu(self.fc1(x)))
        x = self.dropout_fc2(self.relu(self.fc2(x)))
        return self.fc3(x).squeeze(1)

class FocalLoss(nn.Module):
    def __init__(self, alpha=0.25, gamma=2.0):
        super().__init__(); self.alpha = alpha; self.gamma = gamma
    def forward(self, inputs, targets):
        bce = nn.functional.binary_cross_entropy_with_logits(inputs, targets, reduction='none')
        pt = torch.exp(-bce)
        return (self.alpha * (1-pt)**self.gamma * bce).mean()

def train_ep(model, loader, optimizer, criterion):
    model.train(); total = 0; n = 0
    for x, y in loader:
        x, y = x.to(DEVICE), y.to(DEVICE)
        optimizer.zero_grad()
        out = model(x)
        loss = criterion(out, y)
        if not torch.isfinite(loss):
            print('  [NaN guard] loss not finite, skip batch', flush=True)
            continue
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
        optimizer.step()
        total += loss.item() * x.size(0); n += x.size(0)
    return total / max(n, 1)

def evaluate(model, loader, criterion):
    model.eval(); total = 0; probs = []; labels = []
    with torch.no_grad():
        for x, y in loader:
            x, y = x.to(DEVICE), y.to(DEVICE)
            out = model(x)
            total += criterion(out, y).item() * x.size(0)
            probs.extend(torch.sigmoid(out).cpu().numpy()); labels.extend(y.cpu().numpy())
    return total / len(loader.dataset), np.array(probs), np.array(labels)

def metrics(y, p):
    return (accuracy_score(y, p), precision_score(y, p, zero_division=0),
            recall_score(y, p, zero_division=0), f1_score(y, p, zero_division=0))

if __name__ == '__main__':
    os.makedirs(f"{W}/models_op_v2", exist_ok=True)
    lab = pd.read_csv(f"{W}/op_lab_v2.csv")
    wild = pd.read_csv(f"{W}/op_wild_v2.csv")
    lab['opcode_seq'] = lab['opcode_seq'].fillna('').astype(str)
    wild['opcode_seq'] = wild['opcode_seq'].fillna('').astype(str)
    lab = lab[lab['opcode_seq'].str.split().str.len() > 0].reset_index(drop=True)
    wild = wild[wild['opcode_seq'].str.split().str.len() > 0].reset_index(drop=True)
    print(f"Lab {len(lab)} (label分布 {lab['label'].value_counts().to_dict()})", flush=True)
    print(f"Wild {len(wild)} (label分布 {wild['label'].value_counts().to_dict()})", flush=True)

    # 恶意沿用原fold, 良性按skf(42)追加
    mal = lab[lab['filename'].str.startswith('VirusShare_')].reset_index(drop=True)
    ben = lab[~lab['filename'].str.startswith('VirusShare_')].reset_index(drop=True)
    fold_assign = {}
    for i in range(1, 6):
        fold_assign[i] = set(pd.read_csv(f"{SPLIT}/results_fold_{i}.csv", header=None)[0].astype(str).str.replace('VirusShare_','',regex=False).tolist())
    skf = StratifiedKFold(5, shuffle=True, random_state=SEED)
    ben_folds = np.zeros(len(ben), dtype=int)
    for fi, (_, te) in enumerate(skf.split(np.zeros(len(ben)), ben['label']), 1):
        ben_folds[te] = fi
    ben = ben.copy(); ben['_fold'] = ben_folds

    lms, wprobs = [], np.zeros(len(wild))
    wild_rows = wild.reset_index(drop=True)
    wild_labels = wild_rows['label'].astype(int).values
    for fi in range(1, 6):
        te_mal = mal[mal['filename'].str.replace('VirusShare_','',regex=False).isin(fold_assign[fi])]
        te = pd.concat([te_mal, ben[ben['_fold']==fi].drop(columns=['_fold'])]).sample(frac=1, random_state=SEED).reset_index(drop=True)
        tr = pd.concat([mal[~mal['filename'].str.replace('VirusShare_','',regex=False).isin(fold_assign[fi])], ben[ben['_fold']!=fi].drop(columns=['_fold'])]).sample(frac=1, random_state=SEED).reset_index(drop=True)
        print(f"\n== fold{fi}: train {len(tr)} test {len(te)} ==", flush=True)
        import os as _os
        ckpt = f"{W}/models_op_v2/fold{fi}.pth"
        if _os.path.exists(ckpt):
            # 该折已训练过(或部分): 重建vocab需train集, 但vocab随训练集确定 — 直接重建并用ckpt权重
            pass
        trd = OpcodeDataset(tr); vocab = trd.vocab
        ted = OpcodeDataset(te, vocab=vocab)
        trl = DataLoader(trd, batch_size=BATCH_SIZE, shuffle=True)
        tel = DataLoader(ted, batch_size=BATCH_SIZE, shuffle=False)
        model = ImprovedTextCNN_LSTM(len(vocab), EMBEDDING_DIM, MAXLEN).to(DEVICE)
        opt = optim.AdamW(model.parameters(), lr=LEARNING_RATE, weight_decay=1e-4)
        crit = FocalLoss(0.25, 2.0)
        ws = optim.lr_scheduler.LambdaLR(opt, lr_lambda=lambda e: (e+1)/WARMUP_EPOCHS if e < WARMUP_EPOCHS else 1.0)
        cs = optim.lr_scheduler.CosineAnnealingLR(opt, T_max=EPOCHS-WARMUP_EPOCHS, eta_min=1e-6)
        best, noimp = float('inf'), 0
        _skip_train = _os.path.exists(ckpt)
        if _skip_train:
            print(f"  fold{fi}: 发现已有checkpoint, 跳过训练直接评估", flush=True)
        for ep in range(0 if _skip_train else EPOCHS):
            tl = train_ep(model, trl, opt, crit)
            vl, vp, vy = evaluate(model, tel, crit)
            if ep < WARMUP_EPOCHS: ws.step()
            else: cs.step()
            if vl < best:
                best, noimp = vl, 0
                torch.save(model.state_dict(), f"{W}/models_op_v2/fold{fi}.pth")
            else:
                noimp += 1
                if noimp >= PATIENCE: break
        model.load_state_dict(torch.load(f"{W}/models_op_v2/fold{fi}.pth"))
        _, vp, vy = evaluate(model, tel, crit)
        lms.append(metrics(vy, (vp>=0.5).astype(int)))
        wld = OpcodeDataset(wild_rows, vocab=vocab)  # 用本折vocab!
        wl = DataLoader(wld, batch_size=BATCH_SIZE, shuffle=False)
        _, wp, _ = evaluate(model, wl, crit)
        wprobs += wp / 5
        print(f"fold{fi}: {tuple(round(x,4) for x in lms[-1])}", flush=True)
    # Wild 良性FPR
    wy = wild['label'].values
    wpred = (wprobs >= 0.5).astype(int)
    n_ben = int((wy == 0).sum())
    fpr = float(wpred[wy == 0].mean()) if n_ben else -1
    lm = np.mean(lms, axis=0); wm = metrics(wy, wpred)
    print("\n===== 挖矿 OP-BiLSTM v2 结果 =====")
    print(f"Lab(五折): ACC={lm[0]:.4f} PRE={lm[1]:.4f} REC={lm[2]:.4f} F1={lm[3]:.4f}")
    print(f"Wild:      ACC={wm[0]:.4f} PRE={wm[1]:.4f} REC={wm[2]:.4f} F1={wm[3]:.4f}")
    print(f"良性FPR={fpr:.4f} (n={n_ben})")
    import json
    json.dump(dict(task="挖矿OP-BiLSTM", lab=[round(x,4) for x in lm], wild=[round(x,4) for x in wm],
                   benign_fpr=round(fpr,4), n_lab=len(lab), n_wild=len(wild)),
              open(f"{W}/op_miner_v2_results.json","w"), ensure_ascii=False)
    # 保存逐样本预测供良性FPR精确计算
    pd.DataFrame({
        'filename': wild['filename'].values,
        'label': wy,
        'prob': wprobs,
        'pred': wpred,
        'is_benign': (~wild['filename'].astype(str).str.startswith('VirusShare_')).values
    }).to_csv(f"{W}/op_wild_v2_predictions.csv", index=False)
    print("OP_V2_DONE")
