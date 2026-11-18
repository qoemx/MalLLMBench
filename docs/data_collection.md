# Data Collection

## Malware

- VirusShare collections (MD5-named), family classification via AVClass2.
- Temporal split by VirusTotal first-submission date; cutoff **2021-08-22**. Lab = ≤ cutoff, Wild = > cutoff. v2 keeps every v1 malware row untouched.

## Benign (v2 addition)

Collection scripts: `../code/data_processing/dl_*.py` (one per channel), `normalize.py`, `finalize.py`, `make_dataset_v2.py`.

Pipeline:
1. **Download** from official channels: MSYS2/clang64 (package repos), Cygwin, conda (official pkgs), Python.org releases, Mozilla, VirtualBox, DikeDataset (public dataset), THCRULL (Microsoft trusted-hash list).
2. **Extract** inner PE payloads from installers/archives; record `sha256 / package / inner path / size` per file (channel manifests).
3. **Verify**: MZ + PE signature magic check; drop anything failing either.
4. **Dedup**: unique sha256; language-variant family dedup → 7,000 files, 2,495 families.
5. **Assign to tasks**: source-stratified random sampling, seed=42 → 3,000 cryptojacking + 3,000 ransomware (disjoint) + 1,000 spare.
6. **Split**: within task, random Lab 1,000 / Wild 2,000 (NOT time-based — benign software has no meaningful submission-date axis; randomness avoids channel leakage between splits because stratification happens before splitting).

## What we deliberately did NOT do

- No third-party download sites, no cracked-software sources, noVT "clean" verdicts as ground truth (we use official-origin instead).
- No benign dedup against malware by hash only (different hash spaces; benign are sha256, malware MD5) — benign pool cleanliness rests on official provenance.
