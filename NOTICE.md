# NOTICE

## Malicious samples

- Malware identifiers (MD5/SHA256 hashes) in this repository originate from **VirusShare** collections, labeled with **AVClass2**, with Lab/Wild partitions derived from **VirusTotal** first-submission dates (cutoff 2021-08-22).
- **No malicious binaries are redistributed.** Hashes are published as factual identifiers for reproducibility, consistent with VirusShare's EULA. To obtain sample bodies, register at virusshare.com and comply with their terms and your institution's malware-handling policy.

## Benign samples

- The benign population was collected from official package repositories and public benign datasets (MSYS2, Cygwin, conda/Anaconda, Python.org, Mozilla, VirtualBox, DikeDataset, and the benign split of Thcrull/win-exe-malware-analysis on HuggingFace). Collection scripts under `code/data_processing/` document the exact sources and versions.
- Benign binaries are likewise not redistributed; the manifests allow re-downloading identical files from the original sources.

## Third-party methods

- **PE2Prompt** and **AV-Agent** are evaluated as-is from their original publications. Their prompts and runner code are NOT included here; users should obtain them from the original authors' repositories. What we publish are our inputs (feature digests, three-lane confidences), per-sample prediction records, and evaluation code.

## Benchmark results

- All numbers in `results/` are produced by the code in `code/evaluation/` from the shipped per-sample records; see `docs/evaluation_protocol.md` for metric definitions and known caveats (Monte-Carlo prediction-interval wording, M3 grounding semantics).
