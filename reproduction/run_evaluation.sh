#!/usr/bin/env bash
# Recompute paper tables from shipped per-sample records (no LLM calls, no training). v5
set -e
cd "$(dirname "$0")/.."

echo "== STEP 0: hard data-integrity assertions (abort on any failure) =="
python code/evaluation/assert_integrity.py

echo "== Full-Wild detection table (fixed 18 official prediction files) =="
python code/evaluation/classification/compute_metrics.py \
    --pred results/predictions --conf results/conventional \
    --out-dir results/tables

echo "== M1 temperature stability (from shipped 3-run records) =="
python code/evaluation/reliability/temperature_analysis.py

echo "== M2 ReprSet fidelity (own-Wild baselines) =="
python code/evaluation/reprset_fidelity/subset_fidelity.py
python code/evaluation/reprset_fidelity/subset_fidelity_ransom.py
python code/evaluation/reprset_fidelity/render_table.py   # regenerates table_reprset_fidelity.tex

echo "== M3 evidence audit =="
python code/evaluation/content_analysis/m3_evidence_check.py

echo "All tables (incl. LaTeX) regenerated under results/tables/"
