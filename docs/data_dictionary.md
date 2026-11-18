# Data Dictionary

## data/manifests/

### {task}_{split}.csv  (cryptojacking_lab / cryptojacking_wild / ransomware_lab / ransomware_wild)
| Column | Meaning |
|---|---|
| filename | sample identifier (first 16 hex chars; malware = MD5 from VirusShare name, benign = SHA256 prefix) |
| hash | full hash when available |
| label | 1 = target malware, 0 = other malware **or** benign (disambiguate with source) |
| source | `benign` for benign rows; malware rows carry their lane tag |
| file_path | original location (internal; kept for traceability) |

### {task}_wild_malware_labels.csv
Malware-only ground truth (no benign rows), full MD5.

### benign_source_counts.csv / final_manifest.csv
Full 7,000 benign pool: sha256, source channel, family, filename, size.

### reprset_*.txt
Fixed ReprSet sample lists: `sample_id, stratum, label`.

## data/features/{task}/{split}/string_features.csv
TIF string-indicator features:
- Cryptojacking: 86 dims — mining-pool URLs/names, coin names, wallet-address regex hits (BTC/LTC/XMR), mining-algorithm names, CPU/GPU strings, capstone instruction statistics, dictionary hits.
- Ransomware: 47 dims — ransom vocabulary, extortion phrases, crypto APIs, destructive commands (vssadmin etc.), YARA rule hits, flag indicators.
First column `sample_id`; values are counts / binary flags.

## results/conventional/*.csv
Per-sample Wild confidence: `filename, label, prob, pred, is_benign`.

## results/reliability/, results/reprset_fidelity/, results/content_analysis/
See docs/evaluation_protocol.md; formats documented in each folder's outputs (CSV headers self-describing).
