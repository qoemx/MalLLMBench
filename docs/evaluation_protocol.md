# Evaluation Protocol

All metrics computed from shipped per-sample records (`results/`); no re-inference needed.

## 1. Classification

- Full Wild, per method: ACC / PRE / REC / F1 + **benign FPR**.
- **Benign FPR denominator = benign subset only** (is_benign mask), NEVER all label=0 (which includes other-malware negatives). Report mask size alongside.
- Missing predictions (unparsed LLM outputs / missing features) are excluded, never counted as negative; effective n always reported.

## 2. M1 — Prediction stability

- 300-sample stratified set per task (100 target / 100 other / 100 benign, seed=42), identical across methods.
- 3 real runs per temperature ∈ {0, 0.3, 0.7}; AV-Agent runs the full two-phase pipeline; only the FINAL output is compared. PE2 run 1 at T=0 reuses the full-scale predictions (protocol rule, noted in the run file).
- Per-sample disagreement rate: fraction of samples whose 3-run predictions are not all equal (reported overall + per stratum).
- F1 reported as mean ± std over the three runs. Raw per-sample records for all 12 configurations ship in `results/reliability/`.

## 3. M2 — ReprSet fidelity

- 100 independent class-proportionate stratified draws per size ∈ {500, 1000, 1500, 2000, 3000}; selection never uses model predictions.
- E_m(N) = |F1_sub − F1_full| per method; joint success = both methods ≤ 0.05.
- Cost column in the paper: tokens measured per-sample from full-scale run usage records (input+output).

## 4. M3 — Analysis-trace evidence audit

- 120 samples (2 tasks × 20 target / 20 other / 20 benign, seed=42).
- AV-Agent re-run at T=0 with full internal trace persisted; audited claims are those **explicitly stated** in the trace.
- Verdicts: **Supported** (matches independently extracted static features), **Contradicted** (static evidence contradicts), **Unverifiable** (behavioral claims; static evidence can neither confirm nor refute — never counted as errors).
- Semantics caveats: traces are internal execution artifacts, not user-facing explanations; Supported claims were pipeline-injected evidence faithfully relayed — this measures evidence-chain consistency, not independent model knowledge. Absence of an imported API can contradict "imports X" but NEVER proves the program lacks behavior X.
- PE2 natively outputs verdict tokens only → Availability 0%; Grounding/Contradicted recorded as N/A (an auditability gap, not evidence of error).
