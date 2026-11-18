#!/usr/bin/env bash
# MalLLMBench conventional baselines: 5-fold CV on Lab (benign included) → Wild confidence CSVs
# Features: data/features/ (string/TIF); other baselines need features reproduced per docs/reproduction.md
set -e
cd "$(dirname "$0")/.."

echo "== TIF (LightGBM, from shipped string features) =="
python code/conventional_baselines/run_tif.py --task cryptojacking
python code/conventional_baselines/run_tif.py --task ransomware

echo "== Other six baselines (EHm/EHc/PF/RB/OP/CFG-GIN) =="
echo "These require feature files not fully shipped (byte/entropy/opcode/graph inputs)."
echo "See docs/reproduction.md §Conventional baselines for per-cell inputs."
# python code/conventional_baselines/run_ehm.py --task cryptojacking
# ... (uncomment after staging features)

echo "Done. Confidence CSVs written to results/conventional/."
