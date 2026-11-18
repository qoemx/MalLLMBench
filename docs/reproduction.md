# Reproduction

Every number in `results/tables/` regenerates from shipped per-sample records — no LLM calls, no training.

```bash
cd reproduction
pip install -r requirements.txt
bash run_evaluation.sh
```

What `run_evaluation.sh` does, step by step:

| Step | Script | Input | Output |
|---|---|---|---|
| Detection table | `code/evaluation/classification/compute_metrics.py` | `results/predictions/*.csv` + `results/conventional/*.csv` | `results/tables/detection_wild.csv` |
| M1 temperature stability | `code/evaluation/reliability/temperature_analysis.py` | `results/reliability/<method>_<task>/*.jsonl` (3 runs × 3 temps × 4 groups) | `results/reliability/summary_temperature.csv` |
| M2 ReprSet fidelity | `code/evaluation/reprset_fidelity/subset_fidelity{,_ransom}.py` | per-sample predictions + manifests | `results/reprset_fidelity/*.csv/json` |
| M3 evidence audit | `code/evaluation/content_analysis/m3_evidence_check.py` | `results/content_analysis/m3_audit_results.json` | `results/content_analysis/m3_summary.csv` |

## Conventional baselines

```bash
bash run_baselines.sh
```

- **TIF**: fully runnable end-to-end from shipped `data/features/` (label join supports 16-hex malware and 32-hex benign-sha256-prefix id forms).
- **Other six** (EHm/EHc/PF/RB/OP/CFG-GIN): exact training scripts as executed for the paper are in `code/conventional_baselines/` (`v2_exp*.py` + `container_scripts/`); they reference container-side feature stores (512-dim histograms, raw bytes, Ghidra opcode sequences, GDL graphs) that are too large to redistribute. Per-cell Wild outputs ship in `results/conventional/` (14 CSVs = 7 methods × 2 tasks).

## LLM methods

Not redistributed (original authors' artifacts; see paper citations). What we ship so all metrics recompute without re-inference: full-Wild per-sample predictions for both methods and both tasks (`results/predictions/`), AV-Agent phase-1 token records (`avagent_*_phase1_tokens.csv`) so the two-phase cost in the paper table is reconstructible, and all M1 repeated-run records.

## Known caveats

- LLM runs: vLLM batching may introduce minor nondeterminism even at T=0; M1 quantifies this directly.
- Training: fixed seeds; GPU nondeterminism may shift metrics <0.005.
- `avagent_cryptojacking` M1 numbers use the group-common set (289 samples valid across all nine runs) — the paper's caliber; `n` is printed with every row.
