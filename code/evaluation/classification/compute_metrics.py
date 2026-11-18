# Compute paper tables from shipped per-sample records.
# Usage: python compute_metrics.py --pred results/predictions/ --conf results/conventional/ --out results/tables/
import argparse, csv, json, os

def f1_from_counts(tp, fp, fn):
    return 2*tp / max(2*tp + fp + fn, 1)

def from_conf_csv(path):
    rows = list(csv.DictReader(open(path)))
    tp = sum(1 for r in rows if r["pred"]=="1" and float(r["label"])==1)
    fp = sum(1 for r in rows if r["pred"]=="1" and float(r["label"])==0)
    fn = sum(1 for r in rows if r["pred"]=="0" and float(r["label"])==1)
    tn = sum(1 for r in rows if r["pred"]=="0" and float(r["label"])==0)
    ben = [r for r in rows if r["is_benign"]=="True"]
    return dict(n=len(rows), ACC=(tp+tn)/len(rows), PRE=tp/max(tp+fp,1),
                REC=tp/max(tp+fn,1), F1=f1_from_counts(tp,fp,fn),
                benign_FPR=sum(1 for r in ben if r["pred"]=="1")/max(len(ben),1),
                TP=tp, FP=fp, FN=fn, TN=tn)

def from_summary_json(path):
    d = json.load(open(path))
    return {k: d[k] for k in ("n_parsed","ACC","PRE","REC","F1","benign_FPR","TP","FP","FN","TN") if k in d}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pred", required=True)
    ap.add_argument("--conf", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    rows = [["method","task","source_file"] + ["n","ACC","PRE","REC","F1","benign_FPR","TP","FP","FN","TN"]]
    for f in sorted(os.listdir(a.pred)):
        if f.endswith(".json"):
            d = from_summary_json(os.path.join(a.pred, f))
            method, task = f.replace(".json","").split("_", 1)
            task = task.rsplit("_", 2)[0]
            rows.append([method, task, f] + [d.get(k) for k in ["n","ACC","PRE","REC","F1","benign_FPR","TP","FP","FN","TN"]])
    for f in sorted(os.listdir(a.conf)):
        if f.endswith(".csv"):
            d = from_conf_csv(os.path.join(a.conf, f))
            stem = f.replace("_wild_confidence.csv","").replace("_wild_predictions.csv","")
            rows.append([stem.split("_")[0], stem, f] + [d.get(k) for k in ["n","ACC","PRE","REC","F1","benign_FPR","TP","FP","FN","TN"]])
    out = os.path.join(a.out, "detection_wild.csv")
    with open(out, "w", newline="") as fh:
        csv.writer(fh).writerows(rows)
    print("wrote", out, f"({len(rows)-1} method rows)")

if __name__ == "__main__":
    main()
