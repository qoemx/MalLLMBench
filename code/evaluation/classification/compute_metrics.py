# Compute paper tables from shipped per-sample records. v2 — fixed --out handling.
# Usage: python compute_metrics.py --pred results/predictions --conf results/conventional --out-dir results/tables
import argparse, csv, json, os

def f1_from_counts(tp, fp, fn):
    return 2*tp / max(2*tp + fp + fn, 1)

def from_pred_csv(path):
    """Per-sample prediction CSV: sample_id,label,prediction[,input_tokens,...]"""
    rows = list(csv.DictReader(open(path)))
    task_hint = "cryptojacking" if "cryptojacking" in path else "ransomware"
    mani = {}
    for r2 in csv.DictReader(open(f"data/manifests/{task_hint}_wild.csv")):
        h2 = (r2.get("hash") or r2["filename"]).removesuffix(".exe").removeprefix("VirusShare_")[:32]
        mani[h2] = r2.get("source") == "benign"
        mani[h2[:16]] = mani[h2]
    ben = [r for r in rows if mani.get(r["sample_id"][:32], mani.get(r["sample_id"][:16], False))]
    def val(r, k):
        v = r.get(k, "")
        try: return int(v)
        except: return 1 if str(v).lower() in ("ransomware", "cryptominer", "1", "true") else 0
    tp = sum(1 for r in rows if val(r, "prediction") == 1 and val(r, "label") == 1)
    fp = sum(1 for r in rows if val(r, "prediction") == 1 and val(r, "label") == 0)
    fn = sum(1 for r in rows if val(r, "prediction") == 0 and val(r, "label") == 1)
    tn = sum(1 for r in rows if val(r, "prediction") == 0 and val(r, "label") == 0)
    toks = sum(int(r.get("input_tokens", 0) or 0) + int(r.get("output_tokens", 0) or 0) for r in rows)
    bfp = sum(1 for r in ben if val(r, "prediction") == 1) / max(len(ben), 1)
    return dict(n=len(rows), ACC=(tp+tn)/max(len(rows),1), PRE=tp/max(tp+fp,1),
                REC=tp/max(tp+fn,1), F1=f1_from_counts(tp,fp,fn), benign_FPR=bfp,
                TP=tp, FP=fp, FN=fn, TN=tn, total_tokens=toks)

def from_conf_csv(path):
    rows = list(csv.DictReader(open(path)))
    tp = sum(1 for r in rows if r["pred"] == "1" and float(r["label"]) == 1)
    fp = sum(1 for r in rows if r["pred"] == "1" and float(r["label"]) == 0)
    fn = sum(1 for r in rows if r["pred"] == "0" and float(r["label"]) == 1)
    tn = sum(1 for r in rows if r["pred"] == "0" and float(r["label"]) == 0)
    ben = [r for r in rows if r.get("is_benign") == "True"]
    return dict(n=len(rows), ACC=(tp+tn)/max(len(rows),1), PRE=tp/max(tp+fp,1),
                REC=tp/max(tp+fn,1), F1=f1_from_counts(tp,fp,fn),
                benign_FPR=sum(1 for r in ben if r["pred"] == "1")/max(len(ben),1),
                TP=tp, FP=fp, FN=fn, TN=tn)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pred", required=True)
    ap.add_argument("--conf", required=True)
    ap.add_argument("--out-dir", dest="out_dir", required=True)  # DIRECTORY (fixed)
    a = ap.parse_args()
    os.makedirs(a.out_dir, exist_ok=True)
    rows = [["method", "task", "source_file", "n", "ACC", "PRE", "REC", "F1",
             "benign_FPR", "TP", "FP", "FN", "TN", "total_tokens"]]
    OFFICIAL = {"pe2_cryptojacking_wild_predictions.csv","pe2_ransomware_wild_predictions.csv",
                "avagent_cryptojacking_wild_predictions.csv","avagent_ransomware_wild_predictions.csv"}
    for f in sorted(os.listdir(a.pred)):
        if f in OFFICIAL:
            d = from_pred_csv(os.path.join(a.pred, f))
            method, task = f.split("_", 1)
            task = task.rsplit("_", 2)[0]
            rows.append([method, task, f] + [d.get(k) for k in
                ["n","ACC","PRE","REC","F1","benign_FPR","TP","FP","FN","TN","total_tokens"]])
    for f in sorted(os.listdir(a.conf)):
        if f.endswith(".csv") and ("confidence" in f or "predictions" in f):
            d = from_conf_csv(os.path.join(a.conf, f))
            stem = f.replace("_wild_confidence.csv", "").replace("_wild_predictions.csv", "")
            rows.append([stem.split("_")[0], stem, f] + [d.get(k) for k in
                ["n","ACC","PRE","REC","F1","benign_FPR","TP","FP","FN","TN","total_tokens"]])
    out = os.path.join(a.out_dir, "detection_wild.csv")
    with open(out, "w", newline="") as fh:
        csv.writer(fh).writerows(rows)
    print("wrote", out, f"({len(rows)-1} method rows)")

if __name__ == "__main__":
    main()
