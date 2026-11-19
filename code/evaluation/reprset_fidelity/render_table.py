#!/usr/bin/env python3
"""Regenerate table_reprset_fidelity.tex from the two summary JSONs (token costs from per-sample records)."""
import json, csv

def tokens_per_sample():
    out = {}
    for task, fn in [("cryptojacking", "results/predictions/pe2_cryptojacking_wild_predictions.csv"),
                     ("ransomware", "results/predictions/pe2_ransomware_wild_predictions.csv")]:
        t = n = 0
        for r in csv.DictReader(open(fn)):
            t += int(r.get("input_tokens", 0) or 0) + int(r.get("output_tokens", 0) or 0)
            n += 1
        out[("pe2", task)] = t / max(n, 1)
    for task, fn in [("cryptojacking", "results/predictions/avagent_cryptojacking_wild_predictions.csv"),
                     ("ransomware", "results/predictions/avagent_ransomware_wild_predictions.csv")]:
        t = n = 0
        for r in csv.DictReader(open(fn)):
            t += int(r.get("input_tokens", 0) or 0) + int(r.get("output_tokens", 0) or 0)
            n += 1
        # add phase-1 tokens
        for r in csv.DictReader(open(f"results/predictions/avagent_{task}_phase1_tokens.csv")):
            t += int(r.get("input_tokens", 0) or 0) + int(r.get("output_tokens", 0) or 0)
        out[("av", task)] = t / max(n, 1)
    return out

TP = tokens_per_sample()
FULL = {"cryptojacking": 20000, "ransomware": 17422}

def fmt_tok(n):
    return f"{n/1e6:.2f}M"

rows = []
for task, jf in [("Cryptojacking", "cryptojacking_summary.json"), ("Ransomware", "ransomware_summary.json")]:
    d = json.load(open(f"results/reprset_fidelity/{jf}"))
    tkey = task.lower()
    for N in (500, 1000, 1500, 2000, 3000):
        v = d[str(N)]
        n = f"{N:,}"
        pe2c = fmt_tok(N * TP[("pe2", tkey)])
        avc = fmt_tok(N * TP[("av", tkey)])
        save = (1 - N / FULL[tkey]) * 100
        rows.append(f"& {n} & {v['ep_mean']:.4f} & {v['ep_q95']:.4f} & {v['ea_mean']:.4f} & {v['ea_q95']:.4f} & {v['pass_rate']*100:.0f} & {pe2c} & {avc} & {save:.1f} \\\\")

tex = """\\begin{table*}[t]
\\centering
\\caption{F1 fidelity of class-proportionate subsets relative to the full Wild partitions across 100 independent draws. Joint success is the percentage of draws in which both methods deviate by no more than 0.05. Inference cost is measured per method from the full-scale runs. Sample reduction is relative to the full Wild partition.}
\\label{tab:reprset_fidelity}
\\footnotesize
\\setlength{\\tabcolsep}{4pt}
\\renewcommand{\\arraystretch}{1.08}
\\begin{tabular}{llcccccccc}
\\toprule
Task & Subset size
& \\multicolumn{2}{c}{PE2}
& \\multicolumn{2}{c}{AV-Agent}
& Joint success (\\%)
& \\multicolumn{2}{c}{Inference cost (tokens)}
& Sample reduction (\\%) \\\\
\\cmidrule(lr){3-4}
\\cmidrule(lr){5-6}
\\cmidrule(lr){8-9}
& & Mean & 95th pct. & Mean & 95th pct. & & PE2 & AV-Agent & \\\\
\\midrule
\\multirow{5}{*}{Cryptojacking}
""" + rows[0] + """
""" + rows[1] + """
""" + rows[2] + """
""" + rows[3] + """
""" + rows[4] + """
\\midrule
\\multirow{5}{*}{Ransomware}
""" + rows[5] + """
""" + rows[6] + """
""" + rows[7] + """
""" + rows[8] + """
""" + rows[9] + """
\\bottomrule
\\end{tabular}
\\end{table*}
"""
open("results/tables/table_reprset_fidelity.tex", "w").write(tex)
print("tex regenerated from summaries")
