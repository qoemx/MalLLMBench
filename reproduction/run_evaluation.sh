#!/usr/bin/env bash
# Recompute paper tables from shipped per-sample records (no LLM calls, no training). v3
set -e
cd "$(dirname "$0")/.."

echo "== Full-Wild detection table =="
python code/evaluation/classification/compute_metrics.py \
    --pred results/predictions --conf results/conventional \
    --out-dir results/tables

echo "== M1 temperature stability (from shipped 3-run records) =="
python code/evaluation/reliability/temperature_analysis.py

echo "== M2 ReprSet fidelity =="
python code/evaluation/reprset_fidelity/subset_fidelity.py
python code/evaluation/reprset_fidelity/subset_fidelity_ransom.py

echo "== M3 evidence audit =="
python code/evaluation/content_analysis/m3_evidence_check.py

echo "Tables → results/tables/ (detection_wild.csv)"
