# Conventional baseline configs ()

All baselines: 5-fold CV training on Lab (malicious + benign together), full Wild inference, per-sample confidence CSV + 5-fold weights + metrics JSON (triad per experiment).

| Baseline | Model | Input features | Key hyperparameters |
|---|---|---|---|
| EHm | sklearn MLPClassifier | 512-dim byte-histogram+entropy | hidden (128,64), max_iter 300, adam |
| EHc | MalwareDetector CNN | 512-dim reshaped 23x23 | Conv60(k2)+Conv200(k2)+Dense500 |
| PF | LightGBM | 967-dim EMBER-style PE structural | n_est 400, lr 0.08, leaves 63 |
| RB (MalConv) | 1D-CNN | raw bytes | 8 Conv(k=5)+Dense, softmax |
| OP-BiLSTM | BiLSTM + Attention + FocalLoss | Ghidra opcode sequences | hidden 128, 2-layer, warmup+cosine |
| CFG-GIN | 4-layer GIN | CFG graphs (PyG) | hidden 64, 4 rounds |
| TIF | LightGBM | 86/47-dim string indicators | n_est 400, lr 0.08, leaves 63 |

Seeds: 42 everywhere. StratifiedKFold(5, shuffle, 42) where original fold files absent.
Benign FPR: benign-subset denominator only (see docs/evaluation_protocol.md).
