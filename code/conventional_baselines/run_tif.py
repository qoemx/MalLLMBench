#!/usr/bin/env python3
"""Run TIF baseline (LightGBM 5-fold) on shipped string features.
Usage: python run_tif.py --task cryptojacking|ransomware"""
import argparse, csv, os, sys
import numpy as np

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--task", choices=["cryptojacking", "ransomware"], required=True)
    ap.add_argument("--data", default="data/features")
    ap.add_argument("--out", default="results/conventional")
    a = ap.parse_args()

    try:
        import lightgbm as lgb
    except ImportError:
        sys.exit("lightgbm required: pip install lightgbm")

    def load(split):
        rows = list(csv.DictReader(open(f"{a.data}/{a.task}/{split}/string_features.csv")))
        ids = [r["sample_id"] for r in rows]
        X = np.array([[float(v) for k, v in r.items() if k != "sample_id"] for r in rows])
        return ids, X

    lab_ids, XL = load("lab")
    wild_ids, XW = load("wild")

    # Labels come from manifests (label column; benign source rows are label 0)
    lab = {}
    for split in ("lab",):
        fn = f"data/manifests/{a.task}_{split}.csv"
        if os.path.exists(fn):
            for r in csv.DictReader(open(fn)):
                lab[r["filename"]] = int(r["label"])
    yL = np.array([lab.get(i, 0) for i in lab_ids])

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
        probW += m.predict_proba(XW)[:, 1] / 5
        print(f"fold{k+1} done")
    pred = (probW > 0.5).astype(int)
    os.makedirs(a.out, exist_ok=True)
    out = f"{a.out}/{a.task[:6]}_tif_repro_confidence.csv"
    with open(out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["filename", "label", "prob", "pred", "is_benign"])
        for i, p, pr in zip(wild_ids, probW, pred):
            w.writerow([i, lab.get(i, ""), f"{p:.6f}", pr, "TODO_JOIN_MANIFEST"])
    print("wrote", out, "(join labels/is_benign from manifests before use)")

if __name__ == "__main__":
    main()
