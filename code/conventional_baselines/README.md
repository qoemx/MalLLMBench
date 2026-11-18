# Conventional baselines

All 7 baselines × 2 tasks. Two tiers of shipped code:

1. **Fully runnable from this repo**: `run_tif.py` (uses shipped `data/features/`).
2. **Exact training scripts** (as executed for the paper, paths point to the original compute environment — adapt paths to your layout): `v2_exp*.py` and `container_scripts/`. Hyperparameters are the authoritative record; per-experiment data provenance is documented in each cell's `data_manifest.txt` (mirrored in `configs/conventional/README.md`).

| Cell | Method×Task | Code shipped | Notes |
|---|---|---|---|
| 01 | EHm × Ransomware | `v2_exp01_ransom_EHm.py` | 512-dim hist features |
| 02 | PF × Cryptojacking | `v2_exp02_crypto_PF.py` | 967-dim EMBER-style structural |
| 03 | PF × Ransomware | `v2_exp03_ransom_PF.py` | |
| 04 | GI(CFG-GIN) × Ransomware | `v2_exp04_ransom_GI.py` | GIN on CFG graphs |
| 05 | EHm × Cryptojacking | `container_scripts/ehm_entry.py` (conf_all) | MLP |
| 07 | GI(CFG-GIN) × Cryptojacking | `container_scripts/cfg_gin.py` + `gdl_parser.py` | |
| 08/09 | RB(MalConv) × both | `container_scripts/rb_malconv.py`, `malconv_ransomware.py` | |
| 10/11 | OP-BiLSTM × both | `container_scripts/op_bilstm_*.py` | needs Ghidra opcode seqs |
| 12/13 | EHc × both | `container_scripts/ehc.py` | CNN |
| 14 | CFG × both | (in-progress cell, no separate script) | |
| TIF × both | `run_tif.py` | fully runnable from shipped features | ✓ |

Note: EHm×Crypto, GI×Crypto, RB, OP, EHc scripts reference container-side feature directories (512-dim histograms, GDL graphs, opcode sequences, raw bytes) that are too large to redistribute; the scripts document the exact inputs consumed. Per-sample Wild outputs for every cell ship in `results/conventional/`.
