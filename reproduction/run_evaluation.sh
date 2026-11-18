#!/usr/bin/env bash
# Recompute all paper tables from shipped per-sample records (no LLM calls, no training)
set -e
cd "$(dirname "$0")/.."

echo "== Full-Wild detection tables =="
python code/evaluation/classification/compute_metrics.py \
    --pred results/predictions/ --conf results/conventional/ \
    --out results/tables/detection_wild.csv

echo "== M1 stability (incl. Monte-Carlo intervals) =="
python code/evaluation/reliability/mc_intervals.py            # PE2 cryptojacking
python code/evaluation/reliability/temperature_analysis.py    # AV-Agent ransomware (3 temps)

echo "== M2 ReprSet fidelity =="
python code/evaluation/reprset_fidelity/subset_fidelity.py
python code/evaluation/reprset_fidelity/subset_fidelity_ransom.py

echo "== M3 evidence audit =="
python code/evaluation/content_analysis/m3_evidence_check.py

echo "Tables → results/tables/"
