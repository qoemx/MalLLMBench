#!/usr/bin/env python3
"""M3 analysis-trace evidence audit — recompute the three headline metrics
from the shipped per-claim audit records (results/content_analysis/m3_audit_results.json).
(Trace rerun itself requires the original LLM endpoint; see paper protocol.)"""
import json, csv, os
from collections import defaultdict, Counter

d = json.load(open("results/content_analysis/m3_audit_results.json"))
results = d["results"]
table = {}
for task in ("cryptojacking", "ransomware"):
    rs = [r for r in results if r["task"] == task]
    n = len(rs)
    has_ev = sum(1 for r in rs if r["has_evidence"])
    sup = sum(r["n_supported"] for r in rs)
    con = sum(r["n_contradicted"] for r in rs)
    unv = sum(r["n_unverifiable"] for r in rs)
    cbu = sum(1 for r in rs if r["correct_but_contradicted"])
    table[task] = dict(n=n, availability=has_ev/n, grounding=sup/max(sup+con, 1),
                       n_supported=sup, n_contradicted=con, n_unverifiable=unv,
                       correct_but_ungrounded=cbu)
    print(f"{task}: n={n} Availability={has_ev/n*100:.1f}% Grounding={sup/max(sup+con,1)*100:.1f}% "
          f"(Sup {sup}/Con {con}/Unv {unv}) correct-but-contradicted={cbu}")

with open("results/content_analysis/m3_summary.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["task","n","availability","grounding","n_supported","n_contradicted","n_unverifiable","correct_but_ungrounded"])
    for t, v in table.items():
        w.writerow([t, v["n"], f"{v['availability']:.4f}", f"{v['grounding']:.4f}", v["n_supported"], v["n_contradicted"], v["n_unverifiable"], v["correct_but_ungrounded"]])
print("wrote results/content_analysis/m3_summary.csv")
