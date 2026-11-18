#!/usr/bin/env python3
"""M3 Step3: 证据核查 — 从完整轨迹提取可核查事实陈述 → 独立PE静态资产验证
陈述类型: (a)TIF特征计数类(模型引用了输入特征值) (b)API/导入类 (c)字符串存在类 (d)行为类→Unverifiable
核查源: TIF特征pkl(程序化重新计算的独立证据) + ember imports"""
import json, re, pickle
import numpy as np
from collections import Counter, defaultdict

B = "/home/aapt/disk1.7T/aapt-u1_data/work/pe2prompt"

traces = [json.loads(l) for l in open(f"{B}/m3_av_full_traces.jsonl")]
ok = [t for t in traces if t.get("status") == "success"]
print(f"轨迹: {len(ok)}/120")

# TIF独立证据(两任务)
tifs = {}
for task, tr in [("cryptojacking", "/home/aapt/disk1.7T/aapt-u1_data/work/tif_miner_v2"),
                 ("ransomware", "/home/aapt/disk1.7T/aapt-u1_data/work/tif_ransom_v2")]:
    keys = pickle.load(open(f"{tr}/models/keys.pkl", "rb"))
    XW = pickle.load(open(f"{tr}/fe_v2_wild.pkl", "rb"))
    wid = pickle.load(open(f"{tr}/fe_v2_wild_ids.pkl", "rb"))
    tifs[task] = (keys, XW, {m[0][:16]: i for i, m in enumerate(wid)})

# 特征名匹配词典(thinking里引用的输入特征 → TIF键)
FE_KEYMAP = {
    "xmr_count": "xmr_count", "btc_count": "btc_count", "ltc_count": "ltc_count",
    "pool": "pool_count", "pool_name_count": "pool_name_count", "coin": "coin_count",
    "coin_name_count": "coin_name_count", "cpu": "cpu_count", "gpu": "gpu_count",
    "urls": "urls_count", "paths": "paths_count", "ips": "ips_count",
    "ransom_words": "ransom_words_count", "ransom_words_count": "ransom_words_count",
    "extortion": "extortion_count", "extortion_count": "extortion_count",
    "crypto_api": "crypto_api_count", "crypto_api_count": "crypto_api_count",
    "file_api": "file_api_count", "registry_api": "registry_api_count",
    "cmd": "cmd_count", "cmd_count": "cmd_count",
    "opcode_total": "opcode_total", "opcode_unique": "opcode_unique",
    "high_entropy_sections": "high_entropy_sections",
    "aes_present": "aes_present", "rsa_present": "rsa_present",
    "shadow_delete_flag": "shadow_delete_flag", "backup_destroy_flag": "backup_destroy_flag",
    "hybrid_crypto_flag": "hybrid_crypto_flag", "tor_present": "tor_present",
    "algorithm_name_count": "algorithm_name_count",
}

results = []
claim_stats = defaultdict(Counter)
for t in ok:
    task = t["task"]
    keys, XW, wmeta = tifs[task]
    sid = t["sample_id"]
    text = (t.get("raw_phase1_full") or "") + "\n" + (t.get("raw_phase2_full") or "")
    claims = []
    # (a) 特征计数/存在陈述: "xxx_count (N)" 或 "xxx present"
    for pat_name, tif_key in FE_KEYMAP.items():
        if tif_key not in keys:
            continue
        # 模式1: `feature (数字)` 或 feature_count (数字)
        m = re.findall(rf"{pat_name}\s*\((\d+)\)", text)
        true_val = float(XW[wmeta[sid]][keys.index(tif_key)]) if sid in wmeta else None
        for num in m:
            if true_val is not None:
                claims.append(dict(type="feature_count", claim=f"{pat_name}={num}",
                                   verdict="Supported" if abs(true_val - float(num)) <= max(1, 0.15*float(num)) else "Contradicted",
                                   true_val=true_val))
        # 模式2: "xxx present" 而实际为0 → Contradicted
        if re.search(rf"{pat_name}[^.\n]{{0,40}}present", text, re.I) and true_val is not None and true_val == 0:
            claims.append(dict(type="feature_presence", claim=f"{pat_name} present (actual 0)",
                               verdict="Contradicted", true_val=0))
    # (b) 行为陈述: 加密/挖矿/删除等行为动词短语(不可静态核查)
    BEHAVIOR_PATS = [
        r"(?:encrypts?|encryption of)\s+(?:user\s+)?files",
        r"mines?\s+(?:cryptocurrency|coins?)",
        r"deletes?\s+shadow",
        r"communicates?\s+with\s+(?:a\s+)?(?:mining\s+pool|C2)",
        r"modif\w+\s+(?:the\s+)?registry",
        r"executes?\s+(?:arbitrary|shell) code",
    ]
    for bp in BEHAVIOR_PATS:
        if re.search(bp, text, re.I):
            claims.append(dict(type="behavior", claim=bp, verdict="Unverifiable", true_val=None))
    # 汇总
    n_sup = sum(1 for c in claims if c["verdict"] == "Supported")
    n_con = sum(1 for c in claims if c["verdict"] == "Contradicted")
    n_unv = sum(1 for c in claims if c["verdict"] == "Unverifiable")
    has_checkable = n_sup + n_con > 0
    rec = dict(sample_id=sid, task=task, group=t["group"], label=t["label"],
               final=t["final"], correct=(t["final"] == t["label"]),
               n_claims=len(claims), n_supported=n_sup, n_contradicted=n_con, n_unverifiable=n_unv,
               has_evidence=has_checkable,
               correct_but_contradicted=(t["final"] == t["label"] and n_con > 0),
               claims=[dict(c) for c in claims])
    results.append(rec)
    claim_stats[task]["samples"] += 1
    claim_stats[task]["has_evidence"] += has_checkable
    claim_stats[task]["sup"] += n_sup
    claim_stats[task]["con"] += n_con
    claim_stats[task]["unv"] += n_unv
    claim_stats[task]["cbu"] += rec["correct_but_contradicted"]

# ===== 三指标 =====
print("\n== M3 三指标 ==")
table = {}
for task in ("cryptojacking", "ransomware"):
    s = claim_stats[task]
    n = s["samples"]
    # Evidence Availability: 有至少一条可核查陈述的轨迹占比
    avail = s["has_evidence"] / n
    # Evidence Grounding: 有结论陈述中Supported比例
    grounding = s["sup"] / max(s["sup"] + s["con"], 1)
    # Contradicted claims 计数与correct-but-ungrounded
    table[task] = dict(n=n, availability=round(avail, 4), grounding=round(grounding, 4),
                       n_sup=s["sup"], n_con=s["con"], n_unv=s["unv"],
                       contradicted_rate=round(s["con"]/max(s["sup"]+s["con"],1), 4),
                       correct_but_ungrounded=s["cbu"])
    print(f"{task}: Availability={avail*100:.0f}% Grounding={grounding*100:.1f}% "
          f"(Sup {s['sup']} / Con {s['con']} / Unv {s['unv']}) correct-but-contradicted={s['cbu']}/{n}")

json.dump(dict(table=table, results=results), open(f"{B}/m3_audit_results.json", "w"), indent=1)
print("\nm3_audit_results.json saved")

# 真实案例: correct_but_contradicted
cases = [r for r in results if r["correct_but_contradicted"]]
print(f"\n== 真实案例候选(correct分类但含被反驳陈述): {len(cases)} ==")
for c in cases[:3]:
    con = [x for x in c["claims"] if x["verdict"] == "Contradicted"]
    print(f"  {c['task']}/{c['sample_id']} [{c['group']}] 反驳陈述: {[x['claim'] for x in con][:3]}")
