"""
NOTE on TIF reproduction fidelity:
- Cryptojacking: repo retrain reproduces published F1 within 0.001 (0.9294 vs 0.9288).
- Ransomware: repo retrain gives ~0.657 vs published 0.6475. The published confidence CSV
  was produced by the original container pipeline (train_lightGBM.py verbatim, full v2
  split); the difference stems from fold-assignment details (the original reused saved
  fold indices rather than regenerating StratifiedKFold). For paper numbers use the
  published confidence CSVs in results/conventional/; run_tif.py is a faithful-but-
  simplified reimplementation for pipeline verification.
"""
#!/usr/bin/env python3
"""Run TIF baseline (LightGBM 5-fold) on shipped string features. v2 — fixed label join.
Usage: python run_tif.py --task cryptojacking|ransomware

Label join (fixed): features use sample_id == manifests filename (16-hex prefix);
we build the label dict keyed by BOTH filename and hash prefix, then query by sample_id.
"""
import argparse, csv, os, sys
import numpy as np

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--task", choices=["cryptojacking", "ransomware"], required=True)
    ap.add_argument("--data", default="data/features")
    ap.add_argument("--manifests", default="data/manifests")
    ap.add_argument("--out", default="results/conventional")
    a = ap.parse_args()

    try:
        import lightgbm as lgb
    except ImportError:
        sys.exit("lightgbm required: pip install lightgbm")

    # ---- labels: key by filename AND hash prefix (16 chars), so sample_id always hits ----
    def load_labels(split):
        lab = {}
        fn = f"{a.manifests}/{a.task}_{split}.csv"
        for r in csv.DictReader(open(fn)):
            y = int(r["label"])
            if r.get("source") == "benign":
                y = 0  # benign rows always 0 regardless of label column
            for key in (r.get("filename", ""), r.get("hash", "")):
                if key:
                    lab[key] = y
                    lab[key[:16]] = y   # 16-hex malware id form
                    lab[key[:32]] = y   # 32-hex benign sha256-prefix form (ransom features)
        return lab

    lab = load_labels("lab")
    lab_wild = load_labels("wild")
    benign_wild = set()
    for r in csv.DictReader(open(f"{a.manifests}/{a.task}_wild.csv")):
        if r.get("source") == "benign":
            benign_wild.add((r.get("hash") or r["filename"])[:32])
            benign_wild.add((r.get("hash") or r["filename"])[:16])

    def load_features(split, labels):
        rows = list(csv.DictReader(open(f"{a.data}/{a.task}/{split}/string_features.csv")))
        ids, X, ys, missing = [], [], [], 0
        for r in rows:
            sid = r["sample_id"]
            if sid not in labels:
                missing += 1
                continue
            ids.append(sid)
            ys.append(labels[sid])
            X.append([float(v) for k, v in r.items() if k != "sample_id"])
        if missing:
            print(f"  [{split}] {missing} feature rows without labels (skipped)")
        return ids, np.array(X), np.array(ys)

    lab_ids, XL, yL = load_features("lab", lab)
    wild_ids, XW, _ = load_features("wild", lab_wild)
    print(f"lab: {len(yL)} samples, pos={int(yL.sum())}; wild: {len(wild_ids)}")
    assert yL.sum() > 0, "ALL-ZERO TRAINING LABELS — join failed, aborting"

    from sklearn.model_selection import StratifiedKFold
    folds = list(StratifiedKFold(5, shuffle=True, random_state=42).split(XL, yL))
    params = dict(objective="binary", n_estimators=400, learning_rate=0.08,
                  num_leaves=63, subsample=0.9, colsample_bytree=0.9,
                  min_child_samples=20, reg_alpha=0.1, reg_lambda=1.0,
                  random_state=42, verbose=-1)
    probW = np.zeros(len(wild_ids))
    for k, (tr, va) in enumerate(folds):
        m = lgb.LGBMClassifier(**params)
        m.fit(XL[tr], yL[tr])
        from sklearn.metrics import f1_score
        f1va = f1_score(yL[va], (m.predict_proba(XL[va])[:, 1] > 0.5).astype(int))
        print(f"  fold{k+1} val F1={f1va:.4f}")
        probW += m.predict_proba(XW)[:, 1] / 5

    pred = (probW > 0.5).astype(int)
    os.makedirs(a.out, exist_ok=True)
    out = f"{a.out}/{a.task}_tif_repro_confidence.csv"
    with open(out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["filename", "label", "prob", "pred", "is_benign"])
        for i, p, pr in zip(wild_ids, probW, pred):
            w.writerow([i, lab_wild.get(i, ""), f"{p:.6f}", pr, i[:32] in benign_wild or i[:16] in benign_wild])
    print("wrote", out)

if __name__ == "__main__":
    main()
