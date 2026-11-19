#!/usr/bin/env python3
"""CFG-GIN 统一解析器: Ghidra GDL 格式(节点label='Block N\\nStart..\\nEnd..\\n<指令行们>')
图构建: 节点=基本块(跨所有函数), 边=subgraph内的edge + (近似)线性顺序边
特征: 每节点的指令统计15维(原版同款正则) + 图级8维拼节点 => 23维"""
import os, re, glob, time
import numpy as np

TRANSFER = re.compile(r'\b(jmp|je|jne|jz|jnz|jg|jge|jl|jle|ja|jae|jb|jbe|jo|jno|js|jns|loop|br|jump)\b', re.I)
CALL = re.compile(r'\b(call|invoke|syscall|int)\b', re.I)
ARITH = re.compile(r'\b(add|sub|mul|div|inc|dec|and|or|xor|not|shl|shr|imul|idiv)\b', re.I)
CMP = re.compile(r'\b(cmp|test)\b', re.I)
MOVE = re.compile(r'\b(mov|lea|push|pop|load|store)\b', re.I)
TERM = re.compile(r'\b(ret|retn|return|exit|halt)\b', re.I)
CONST = re.compile(r'\b\d+\b')

_cache = {}
def instr_features(txt):
    if not txt: return [0.0]*15
    h = hash(txt)
    if h in _cache: return _cache[h]
    t = txt.lower()
    f = [float(len(CONST.findall(t))), float(len(TRANSFER.findall(t))), float(len(CALL.findall(t))),
         float(len(ARITH.findall(t))), float(len(CMP.findall(t))), float(len(MOVE.findall(t))),
         float(len(TERM.findall(t))),
         float(len(TRANSFER.findall(t))+len(CALL.findall(t))+len(ARITH.findall(t))+len(CMP.findall(t))+len(MOVE.findall(t))+len(TERM.findall(t)))]
    apis = ['createfile','openprocess','virtualalloc','writeprocessmemory','loadlibrary','getprocaddress','regsetvalue','regqueryvalue','socket','connect','send','recv']
    mal = ['inject','hook','bypass','obfuscat','encrypt','decrypt','pack','unpack']
    net = ['http','tcp','udp','socket','send','recv','connect','bind','listen']
    fil = ['file','read','write','create','delete','copy','move']
    reg = ['reg','hkey','software','currentversion','run','startup']
    prc = ['process','thread','create','terminate','suspend','resume']
    f += [float(sum(1 for p in apis if p in t)), float(sum(1 for p in mal if p in t)),
          float(sum(1 for p in net if p in t)), float(sum(1 for p in fil if p in t)),
          float(sum(1 for p in reg if p in t)), float(sum(1 for p in prc if p in t)),
          min(len(txt)/100.0, 10.0)]
    _cache[h] = f
    return f

NODE_RE = re.compile(r'node:\s*\{\s*title:\s*"([^"]*)"\s*label:\s*"((?:[^"\\]|\\.)*)"\s*\}', re.S)
EDGE_RE = re.compile(r'edge:\s*\{\s*sourcename:\s*"([^"]*)"\s*targetname:\s*"([^"]*)"')

def parse_gdl(path, max_nodes=3000):
    try:
        txt = open(path, errors='ignore').read()
    except Exception:
        return None
    nodes = NODE_RE.findall(txt)
    if not nodes: return None
    nodes = nodes[:max_nodes]
    # label 里的 \n 是字面转义
    labels = [l.replace('\\n', '\n') for _, l in nodes]
    titles = [t for t, _ in nodes]
    # 指令部分 = label 去掉 Block/Start/End 头部行
    def instr_part(lab):
        lines = lab.split('\n')
        body = lines[3:] if len(lines) > 3 and lines[0].startswith('Block') else lines
        return '\n'.join(body)
    x = np.array([instr_features(instr_part(l)) for l in labels], dtype=np.float32)
    nmap = {t: i for i, t in enumerate(titles)}
    edges = EDGE_RE.findall(txt)
    src, dst = [], []
    for s, t in edges:
        if s in nmap and t in nmap:
            src.append(nmap[s]); dst.append(nmap[t])
    # 线性顺序边(subgraph内相邻块, 近似块序列) — Ghidra GDL的edge可能只在函数间; 用title同函数前缀相邻补边
    import collections
    groups = collections.defaultdict(list)
    for i, t in enumerate(titles):
        groups[t.rsplit('_', 1)[0]].append(i)
    for g in groups.values():
        for a, b in zip(g, g[1:]):
            src.append(a); dst.append(b)
    ei = np.array([src, dst], dtype=np.int64) if src else np.zeros((2, 0), dtype=np.int64)
    # 图级8维
    out_deg = np.bincount(ei[0], minlength=len(titles)) if ei.size else np.zeros(len(titles))
    gf = np.array([len(titles), ei.shape[1] if ei.size else 0,
                   out_deg.mean() if len(titles) else 0, out_deg.mean(),
                   out_deg.max() if len(titles) else 0, out_deg.max() if len(titles) else 0,
                   out_deg.std() if len(titles) else 0, out_deg.std() if len(titles) else 0], dtype=np.float32)
    x = np.hstack([x, np.tile(gf, (len(titles), 1))])
    return x, ei
