#!/usr/bin/env python3
"""M3 Step2: AV-Agent 120样本完整管线重跑(T=0原配置), 持久化完整原始响应"""
import json, os, time, threading, re, pickle
import numpy as np
from openai import OpenAI

B = "./workspace"
TR_M = "./workspace/features/cryptojacking"
TR_R = "./workspace/features/ransomware"
MODEL = "qwen38-27b"
PORTS = [8001, 8002]

audit = json.load(open(f"{B}/m3_audit_120.json"))

# 全量Phase1输入(两任务)
p1_files = {"cryptojacking": f"{B}/avagent_miner_v2_phase1.jsonl",
            "ransomware": f"{B}/avagent_ransom_v2_phase1.jsonl"}
p1_inputs = {t: {} for t in p1_files}
for t, fn in p1_files.items():
    for l in open(fn):
        d = json.loads(l)
        p1_inputs[t][d["sample_id"][:16]] = d

# TIF特征(两任务)
tifs = {}
for t, tr in [("cryptojacking", TR_M), ("ransomware", TR_R)]:
    keys = pickle.load(open(f"{tr}/models/keys.pkl", "rb"))
    XW = pickle.load(open(f"{tr}/fe_v2_wild.pkl", "rb"))
    wid = pickle.load(open(f"{tr}/fe_v2_wild_ids.pkl", "rb"))
    XL = pickle.load(open(f"{tr}/fe_v2_lab.pkl", "rb"))
    Xall = np.vstack([XL, XW])
    stats = {k: dict(p75=float(np.percentile(Xall[:, i], 75)), p90=float(np.percentile(Xall[:, i], 90)))
             for i, k in enumerate(keys)}
    tifs[t] = (keys, XW, {m[0]: i for i, m in enumerate(wid)}, stats)

FE_M = {
    "pool": "mining pool URLs", "pool_name_count": "mining pool names", "coin": "cryptocurrency names",
    "coin_name_count": "cryptocurrency names", "cpu": "CPU-related strings", "gpu": "GPU-related strings",
    "btc": "Bitcoin wallet addresses", "ltc": "Litecoin wallet addresses", "xmr": "Monero wallet addresses",
    "urls": "URL strings", "paths": "file paths", "regs": "registry strings",
    "algorithm_name_count": "mining algorithm names", "opcode_total": "disassembled instruction volume",
    "opcode_uniq": "instruction diversity", "high_entropy_sections": "high-entropy sections",
}
FE_R = {
    "ransom_words": "ransom vocabulary (ransom/decrypt/encrypt/payment/locked)",
    "extortion": "extortion language (your files/bitcoin/wallet/tor/deadline)",
    "crypto_api": "crypto APIs (CryptEncrypt/AES/RSA)",
    "btc": "Bitcoin wallet addresses", "ltc": "Litecoin wallet addresses", "xmr": "Monero wallet addresses",
    "file_api": "file-manipulation APIs", "cmd": "destructive commands (vssadmin/wbadmin/bcdedit)",
    "registry_api": "registry manipulation", "urls": "URL strings", "paths": "file paths",
    "shadow_delete_flag": "shadow-copy deletion indicator", "backup_destroy_flag": "backup destruction indicator",
    "recovery_disable_flag": "recovery disabling indicator", "hybrid_crypto_flag": "hybrid AES+RSA encryption indicator",
    "aes_present": "AES presence", "rsa_present": "RSA presence",
    "high_entropy_sections": "high-entropy sections", "opcode_total": "disassembled instruction volume",
}

def fe_text(t, vec):
    keys, _, _, stats = tifs[t]
    M = FE_M if t == "cryptojacking" else FE_R
    L = []
    for k, v in zip(keys, vec):
        if k not in stats or v == 0: continue
        st = stats[k]; meaning = M.get(k, k)
        if k.endswith("_flag") or k.endswith("_present"):
            L.append(f"{meaning} present.")
        elif v >= st["p90"]: L.append(f"High {meaning} ({v:.0f}).")
        elif v >= st["p75"]: L.append(f"Moderate {meaning} ({v:.0f}).")
    return " ".join(L[:12]) if L else "No notable indicators present."

def cfg_text(rec):
    return f"[Structural proxy for control-flow complexity] cfg classifier confidence={rec['cfg_conf']:.3f}."

def rb_text(t, vec):
    keys, _, _, _ = tifs[t]
    kd = dict(zip(keys, vec))
    fs = kd.get("file_size", 0); he = kd.get("high_entropy_sections", 0); ot = kd.get("opcode_total", 0)
    return (f"Byte-level statistics: file size={'large' if fs > 3e6 else ('medium' if fs > 3e5 else 'small')}, "
            f"high-entropy sections={he:.0f}, instruction volume={'high' if ot > 2000 else ('medium' if ot > 200 else 'low')}.")

SYS_M = """You are a helpful malware analysis expert. You are a CAUTIOUS malware analysis expert who does not make decisions to overturn previous analysis results lightly.The precision You need to improve the precision of your classification to avoid excessive misclassification, which could lead to a decline in user experience. The precision of classification is EXTREMELY important; thus, it is not necessary for your classifier to identify every miner sample. You need to determine whether the sample to be tested is a type of malware that mines cryptocurrency (miner) based on the given information.

### CONTEXT：
The current stage is the second phase of classifying this sample. In the first phase, a preliminary label was output by assessing the sample's classification confidence across different classifiers. In the second phase, you need to determine whether the sample's classification result is accurate based on the key features of the classification model. When you are checking, you should not be overly aggressive in treating all samples as potential miner samples, as this could lead to a serious precision crisis and affect the reputation of the product.

### INPUT:
sample {hash} has the result of first phrase is {step1_result}
sample {hash} has the key features：
the critical character features,{key_fe}
the key CFG features,{key_cfg}
the essential raw byte features,{raw_bytes}

### INSTRUCTION:
Your outputs should follow this structure:

1. Begin with a <thinking> section.
2. Inside the thinking section:
   a. analysis this sample based on the given results{step1_result}.
   b. Do not modify the results unless you have compelling evidence to prove that the previous conclusions were incorrect.
3. Close the thinking section with </thinking>.
4. Provide your final answer in an <output> section.
   a. give the analysis result.
   b. the result in the <output> should be output as json style like: {{"result":"miner/non-miner"}}"""

SYS_R = SYS_M.replace("identify every miner sample", "identify every ransomware sample").replace(
    "malware that mines cryptocurrency (miner)", "ransomware").replace(
    "potential miner samples", "potential ransomware samples").replace(
    "miner/non-miner", "ransomware/non-ransomware")

clients = {p: OpenAI(api_key="none", base_url=f"http://127.0.0.1:{p}/v1", timeout=240, max_retries=0) for p in PORTS}

def parse_av(text, task):
    t = text or ""
    m = re.search(r"<output>\s*(\{.*?\})\s*</output>", t, re.S)
    if m:
        try:
            j = json.loads(m.group(1)); r = str(j.get("result", "")).lower()
            if task == "cryptojacking":
                if "non" in r and "miner" in r: return 0
                if "miner" in r: return 1
            else:
                if "non" in r: return 0
                if "ransom" in r: return 1
        except Exception: pass
    kw = "miner" if task == "cryptojacking" else "ransomware"
    m2 = re.search(rf'"result"\s*:\s*"((?:non-)?{kw})"', t)
    if m2: return 0 if "non" in m2.group(1) else 1
    m3 = re.search(rf'(?:classif|verdict|conclu|therefore|final answer)[^.\n]{{0,200}}?(non[-_ ]?{kw}|{kw})', t, re.I)
    if m3: return 0 if "non" in m3.group(1).lower() else 1
    return None

lock = threading.Lock()
fout = open(f"{B}/m3_av_full_traces.jsonl", "a", encoding="utf-8")

def one(task, item):
    s16 = item["sample_id"]
    r = p1_inputs[task].get(s16)
    if not r:
        with lock:
            fout.write(json.dumps(dict(sample_id=s16, task=task, group=item["group"], label=item["label"],
                                       status="no_input"))+"\n")
        return
    port = PORTS[hash(s16) % 2]
    # Phase1 完整持久化
    raw1 = p1pred = None
    for attempt in range(5):
        try:
            resp = clients[port].chat.completions.create(
                model=MODEL,
                messages=[{"role": "system", "content": r["sys_p1"]},
                          {"role": "user", "content": r["user_p1"]}],
                temperature=0, max_tokens=1500,
                extra_body={"chat_template_kwargs": {"enable_thinking": False}})
            raw1 = resp.choices[0].message.content or ""
            p1pred = parse_av(raw1, task)
            if p1pred is not None: break
        except Exception:
            time.sleep(2*(attempt+1))
    # Phase2 完整持久化
    raw2 = final = None
    if p1pred is not None:
        keys, XW, wmeta, stats = tifs[task]
        sid32 = r["sample_id"]
        if sid32 in wmeta:
            vec = XW[wmeta[sid32]]
            kw = "miner" if task == "cryptojacking" else "ransomware"
            step1 = kw if p1pred == 1 else ("non-"+kw)
            tmpl = SYS_M if task == "cryptojacking" else SYS_R
            sysp = tmpl.format(hash=s16, step1_result=step1, key_fe=fe_text(task, vec),
                               key_cfg=cfg_text(r), raw_bytes=rb_text(task, vec))
            for attempt in range(5):
                try:
                    resp2 = clients[PORTS[(hash(s16)+1) % 2]].chat.completions.create(
                        model=MODEL,
                        messages=[{"role": "system", "content": sysp},
                                  {"role": "user", "content": "Analyze whether these features support the first-phase result."}],
                        temperature=0, max_tokens=3000,
                        extra_body={"chat_template_kwargs": {"enable_thinking": False}})
                    raw2 = resp2.choices[0].message.content or ""
                    final = parse_av(raw2, task)
                    if final is not None: break
                except Exception:
                    time.sleep(2*(attempt+1))
    rec = dict(sample_id=s16, task=task, group=item["group"], label=item["label"],
               phase1=p1pred, final=final if final is not None else p1pred,
               raw_phase1_full=raw1 or "", raw_phase2_full=raw2 or "",
               status="success" if (final is not None or p1pred is not None) else "unparsed")
    with lock:
        fout.write(json.dumps(rec, ensure_ascii=False)+"\n"); fout.flush()

done = set()
if os.path.exists(f"{B}/m3_av_full_traces.jsonl"):
    for l in open(f"{B}/m3_av_full_traces.jsonl"):
        try:
            d = json.loads(l)
            if d.get("status") in ("success",):
                done.add((d["task"], d["sample_id"]))
        except: pass

jobs = []
for task in ("cryptojacking", "ransomware"):
    for item in audit[task]:
        if (task, item["sample_id"]) not in done:
            jobs.append((task, item))
print(f"待跑: {len(jobs)}/120", flush=True)
t0 = time.time()
for b in range(0, len(jobs), 12):
    batch = jobs[b:b+12]
    ths = [threading.Thread(target=one, args=(t, i)) for t, i in batch]
    for th in ths: th.start()
    for th in ths: th.join()
    print(f"{min(b+12, len(jobs))}/{len(jobs)} ({(time.time()-t0)/60:.0f}min)", flush=True)
fout.close()
print("M3_TRACES_DONE", flush=True)
