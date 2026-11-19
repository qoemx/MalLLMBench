# MalLLMBench — Anonymous Artifact (double-blind review)

**A benchmark for evaluating LLM-assisted malware analysis on Cryptojacking and Ransomware detection, with benign-population controls, stability/fidelity/content-audit protocols.**

> This repository is an anonymized artifact submission. Author information is withheld for double-blind review.

MalLLMBench measures not only *classification accuracy* but three additional dimensions that conventional benchmarks miss:

- **M1 — Prediction stability**: repeated-inference consistency across temperatures (0 / 0.3 / 0.7).
- **M2 — ReprSet fidelity**: how small a fixed representative subset (2,000 samples per task) can approximate full-scale Wild performance (≤0.05 F1 deviation) at ~10% of the inference cost.
- **M3 — Analysis-trace evidence audit**: whether methods expose auditable evidence claims, and whether those claims are grounded in independently verifiable static artifacts.

## Tasks

| Task | Goal | Lab (train) | Wild (test) |
|---|---|---|---|
| Cryptojacking detection | cryptojacking vs other malware vs benign | 6,999 | 20,000 |
| Ransomware detection | ransomware vs other malware vs benign | 7,000 | 17,422 |

Both tasks use the same v2 benign population: 3,000 curated benign PEs per task (disjoint across tasks, seed=42), drawn from a 7,000-sample pool of officially-sourced Windows software.

## Dataset statistics

| Split | Target malware | Other malware | Benign | Total |
|---|---|---|---|---|
| Cryptojacking Lab | 2,000 | 3,999 | 1,000 | 6,999 |
| Cryptojacking Wild | 6,000 | 12,000 | 2,000 | 20,000 |
| Ransomware Lab | 2,000 | 4,000 | 1,000 | 7,000 |
| Ransomware Wild | 5,140 | 10,282 | 2,000 | 17,422 |

Total: **51,421 unique task-specific records**. Two VirusShare hashes (`373c443e…` in Cryptojacking Lab, `f913a9a1…` in Ransomware Wild) each appeared on duplicate rows with conflicting labels in the source CSVs; the authoritative label (verified against the original label sources) is malware-positive=1, and one row per hash is retained (deduplicated). Cryptojacking Lab therefore has 6,999 rows and Ransomware Wild 17,422.

Full Wild detection performance (F1):

| Method | Cryptojacking Wild | Ransomware Wild |
|---|---|---|
| PE2Prompt (LLM, qwen38-27b) | 0.5268 | 0.4064 (voting variant; single-word variant degenerates to 0.0) |
| AV-Agent (two-phase pipeline, qwen38-27b) | 0.8475 | 0.5357 |
| 7 conventional baselines (EHm, EHc, PF, RB/MalConv, OP-BiLSTM, CFG-GIN, TIF) | see `results/tables/detection_wild.csv` | see `results/tables/detection_wild.csv` |

## Data sources & construction

- **Malware**: VirusShare collections, labeled via AVClass2; Lab/Wild split by VirusTotal first-submission date (cutoff **2021-08-22**: Lab ≤ cutoff, Wild > cutoff). Malware rows are identical to the published v1 splits — v2 only *adds* benign samples.
- **Benign**: 7,000 unique PEs (2,495 families) from official channels only — MSYS2, Cygwin, conda, Python.org, Mozilla, VirtualBox, DikeDataset, THCRULL (Microsoft trusted-hash list). Every file passed MZ+PE magic verification and sha256 dedup; no language-variant duplicates. Per task 3,000 benign were drawn by source-stratified random sampling (seed=42), then split Lab 1,000 / Wild 2,000. **Benign assignment is random, not time-based.**
- **No binaries in this repository.** We publish sample hashes, labels, splits, features, per-sample predictions and evaluation code only. Malicious binaries must be obtained from VirusShare under their EULA; benign software from the original official sources (download scripts under `code/data_processing/` document the exact provenance).

## What's in the box

```
data/manifests/     sample hashes, labels, splits, benign provenance, ReprSet IDs (2,000 per task)
data/features/      static string-indicator features (TIF) for all 4 task×split cells
code/data_processing/       benign collection scripts + v2 dataset assembly
code/conventional_baselines/ all 7 baselines: TIF fully runnable + exact v2 training scripts
code/evaluation/    M1 stability / M2 subset fidelity / M3 evidence audit
results/predictions/        full-Wild PER-SAMPLE predictions for PE2 & AV-Agent (both tasks)
results/conventional/       per-sample confidence CSVs for the 7 baselines
results/reliability/        M1 complete three-run records per temperature (both methods × both tasks)
results/reprset_fidelity/   M2 subset experiment details (100 draws × 5 sizes × 2 tasks)
results/content_analysis/   M3 audit records (120 samples)
reproduction/       environment + run instructions
```

## LLM methods

The two evaluated LLM methods are **not** redistributed here; use the original artifacts (cited in the paper as [PE2Prompt] and [AV-Agent]):

- **PE2Prompt** — we used the authors' official 0.7p prompt-formation scripts verbatim (task vocabulary swapped only).
- **AV-Agent** — two-phase agent review; we provide the exact *inputs* we fed it (three-lane confidence values and feature digests, reconstructible from `data/` + `results/conventional/`) and our evaluation code.

Model used in all reported LLM runs: **qwen38-27b** (local vLLM, temperature 0 unless stated, thinking mode disabled).

## Evaluation protocols

See `docs/evaluation_protocol.md` for the full spec. Summary:

1. **Classification**: full-Wild ACC/PRE/REC/F1 + benign-only FPR (denominator = benign subset only).
2. **M1 Stability**: 300-sample stratified set (100 target / 100 other-malware / 100 benign, seed=42), 3 real runs per temperature {0, 0.3, 0.7}; per-sample disagreement rate; F1 mean±std. All 12 (method × task × temperature) configurations' raw run records are shipped under `results/reliability/`.
3. **M2 ReprSet fidelity**: 100 independent class-proportionate draws per size {500..3,000}; |F1_sub − F1_full| per method; joint success = both ≤ 0.05. Token costs measured per-sample from run usage records.
4. **M3 Evidence audit**: 120 samples (2 tasks × 20/20/20, seed=42); claims extracted from AV-Agent internal analysis traces; verdicts **Supported / Contradicted / Unverifiable** against independently extracted static features. PE2 natively emits no rationale → Availability 0%, other metrics N/A. Traces are *internal execution artifacts*, not user-facing explanations; behavioral assertions are never counted as errors when static evidence cannot confirm them.

## Reproduction

```bash
cd reproduction
pip install -r requirements.txt
bash run_evaluation.sh   # recomputes all tables from shipped per-sample records (no LLM calls)
bash run_baselines.sh    # retrains the TIF baseline from shipped features
```

Every number in `results/tables/` is regenerated by `run_evaluation.sh` from the shipped per-sample records. LLM-side reproduction requires obtaining the original method code (see above) plus a qwen38-27b endpoint.

## Limitations & safe use

- Benign pool is developer/sysadmin-tool heavy (MSYS2/Cygwin/Python ≈ 66%); consumer-application coverage is limited — FPR conclusions generalize to "everyday software" only with caution.
- M3 Grounding reflects *consistency with injected feature digests* (the agent faithfully relays pipeline-injected evidence), not independent model knowledge.
- **Safe handling**: this repository contains no executable malware, only hashes/features/predictions. Researchers needing live samples must comply with VirusShare's terms and their institution's malware-handling policy. See `docs/safe_handling.md`.

## Citation

Anonymous artifact for double-blind review. A citable entry with author information will be provided upon acceptance.

## License

- Code: MIT
- Data (manifests/features/predictions): CC BY-NC 4.0

See `LICENSE` and `NOTICE.md`. Malware hashes originate from VirusShare and are published as factual identifiers under their EULA; sample bodies are NOT redistributed.
