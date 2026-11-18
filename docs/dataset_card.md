# Dataset Card — MalLLMBench v2

## Summary

MalLLMBench v2 augments the original (malicious-only) Cryptojacking and Ransomware detection datasets with a curated benign population, yielding two tasks × two splits with realistic benign controls:

| Split | Target | Other malware | Benign | Total |
|---|---|---|---|---|
| Cryptojacking Lab | 2,000 | 4,000 | 1,000 | 7,000 |
| Cryptojacking Wild | 6,000 | 12,000 | 2,000 | 20,000 |
| Ransomware Lab | 2,000 | 4,000 | 1,000 | 7,000 |
| Ransomware Wild | 5,141 | 10,282 | 2,000 | 17,423 |

Total: 51,423 task-specific records.

## Malware side (unchanged from v1)

- Source: VirusShare; family labels via AVClass2.
- Lab/Wild partition: VirusTotal first-submission date, cutoff **2021-08-22** (Lab ≤ cutoff, Wild > cutoff). The v2 release does not touch any v1 malware row.

## Benign side (new in v2)

- Pool: 7,000 unique PE files (2,495 software families), sha256-named, MZ+PE dual-verified.
- Channels: MSYS2 (2,521), DikeDataset (1,113), Python.org (1,014), THCRULL trusted-hash list (903), Cygwin (800), conda (271), VirtualBox (224), Mozilla (142), clang64 (12).
- Per task: 3,000 drawn by source-stratified random sampling (seed=42); the two tasks' benign sets are disjoint; 1,000 spare.
- Within task: Lab 1,000 / Wild 2,000 by the same random rule. **Benign split is NOT time-based** — this is intentional and documented as such.
- `benign =` label 0 with `source=benign` in the manifests; never infer benign status from filename shape.

## Known gaps

- 60 Cryptojacking-Wild PE2 records lack EMBER prompts (oversized binaries); PE2 metrics computed on 19,940/20,000.
- 19 Ransomware-Wild other-malware records lack PE2 predictions (17,403/17,422 effective).
- OP-BiLSTM effective n after empty-sequence filtering: 16,780 (Cryptojacking) / 16,962 (Ransomware).

## ReprSet (representative subsets)

- Cryptojacking: 2,000 (fixed, seed=42) — joint ≤0.05 fidelity in 99% of draws.
- Ransomware: 1,500 (fixed, seed=42) — 96% of draws; a unified 2,000 variant can be regenerated with `code/evaluation/reprset_fidelity/subset_fidelity_ransom.py`.
