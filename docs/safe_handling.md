# Safe Handling

- This repository contains **no executable files** — only hashes, feature vectors, per-sample predictions, and code. Nothing here can execute malware.
- **Obtaining malicious samples**: malware hashes come from VirusShare. To obtain binaries, register at virusshare.com, follow their EULA, and comply with your institution's malware-handling policy (isolated analysis VMs, no production-network exposure). We do not provide samples and will not respond to redistribution requests.
- **Obtaining benign samples**: re-download from official sources using `code/data_processing/dl_*.py` + manifests; verify sha256 against `benign_source_counts.csv` / `final_manifest`.
- **Responsible research**: benchmark numbers must not be used to claim "X% of real-world software is malicious" or similar; class proportions are experimental design choices, not world statistics.
