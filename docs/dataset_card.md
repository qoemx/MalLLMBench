# Dataset Card — MalLLMBench

## Summary

MalLLMBench provides Cryptojacking and Ransomware detection with a curated benign population, yielding two tasks × two splits with realistic benign controls:

| Split | Target | Other malware | Benign | Total |
|---|---|---|---|---|
| Cryptojacking Lab | 2,000 | 3,999 | 1,000 | 6,999 |
| Cryptojacking Wild | 6,000 | 12,000 | 2,000 | 20,000 |
| Ransomware Lab | 2,000 | 4,000 | 1,000 | 7,000 |
| Ransomware Wild | 5,141 | 10,281 | 2,000 | 17,422 |

Total: 51,421 unique task-specific records (two source-side duplicate rows deduplicated; authoritative label = malware-positive).

## Malware side

- Source: VirusShare; family labels via AVClass2.
- Lab/Wild partition: VirusTotal first-submission date, cutoff **2021-08-22** (Lab ≤ cutoff, Wild > cutoff).

## Benign side

- Pool: 7,000 unique PE files (2,495 software families), sha256-named, MZ+PE dual-verified.
- Channels: MSYS2 (2,521), DikeDataset (1,113), Python.org (1,014), Thcrull/win-exe-malware-analysis benign split on HuggingFace — PortableApps/SysinternalsSuite/.NET (903), Cygwin (800), conda (271), VirtualBox (224), Mozilla (142), MSYS2-clang64 (12).
- Each task uses its OWN benign set: 3,000 for Cryptojacking and a completely disjoint 3,000 for Ransomware (intersection = 0, verified), both drawn by source-stratified random sampling (seed=42); 1,000 pool files remain unused.
- Within task: Lab 1,000 / Wild 2,000 by the same random rule. **Benign split is NOT time-based** — this is intentional and documented as such.
- `benign =` label 0 with `source=benign` in the manifests; never infer benign status from filename shape.

## Known gaps

- 60 Cryptojacking-Wild PE2 records lack EMBER prompts (oversized binaries); PE2 metrics computed on 19,940/20,000.
- 19 Ransomware-Wild other-malware records lack PE2 predictions (17,403/17,422 effective).
- OP-BiLSTM effective n after empty-sequence filtering: 16,780 (Cryptojacking) / 16,961 (Ransomware).

## ReprSet (representative subsets)

- Both tasks: 2,000 (fixed, seed=42, class-proportionate) — joint ≤0.05 F1 fidelity in 99% (Cryptojacking) / 98% (Ransomware) of draws, at ~10% of full-scale inference cost.
- Lists: `reprset_cryptojacking_2000.txt` / `reprset_ransomware_2000.txt` (sample_id, stratum, label).
