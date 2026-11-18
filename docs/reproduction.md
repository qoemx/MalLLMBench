# Reproduction Guide

## Environment

```bash
cd reproduction
pip install -r requirements.txt
# or: conda env create -f environment.yml && conda activate malllmbench
```

Core deps: python≥3.10, numpy, pandas, scikit-learn, lightgbm, torch (for CFG-GIN / EHc / OP / RB). Ghidra needed only if re-extracting opcode/CFG features from binaries you lawfully obtained (not required for shipped features).

## Conventional baselines

`bash run_baselines.sh` — retrains each baseline with 5-fold CV on Lab (benign included) and produces Wild per-sample confidence CSVs identical in format to `results/conventional/`. Configs in `configs/conventional/`.

Expected runtimes (single modern GPU): EHm ≈10 min; EHc ≈40 min; RB ≈1 h; PF ≈15 min; TIF ≈5 min; OP ≈2 h (needs opcode sequences); CFG-GIN ≈1.5 h (needs GDL graphs).

## LLM methods (partial reproduction)

The LLM method implementations (PE2Prompt, AV-Agent) are NOT redistributed — obtain them from the original authors (see README). To reproduce OUR runs:

1. Rebuild per-sample inputs from `data/` + `results/conventional/` (three-lane confidences + feature digests) — scripts in `code/evaluation/` show the exact join logic.
2. Serve qwen38-27b (vLLM, temperature as specified per experiment, thinking disabled).
3. Use the original methods' prompts; our per-sample prediction records ship in `results/` so **all paper tables can be recomputed without any re-inference**.

## Recompute paper tables

`bash run_evaluation.sh` — regenerates every table in `results/tables/` from shipped records (deterministic; seeds fixed at 42 where sampling is involved).

## Known non-determinism

- LLM runs: vLLM batching can introduce minor token-level nondeterminism even at T=0; our stability analysis (M1) quantifies this directly.
- Training: fixed seeds everywhere; GPU nondeterminism may shift metrics by <0.005.
