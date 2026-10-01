"""Sanity check of a synthesizer variant: generate on held-out prompts and count schema-valid outputs."""
import sys, json, random, torch
import synth as S
from verifier import parse_rule
from llm_server import Engine

mode = sys.argv[1]            # e.g. "merge:sft=../models/adapters/sft.pt" or "sft=../models/adapters/sft.pt"
n = int(sys.argv[2]) if len(sys.argv) > 2 else 24
R = [json.loads(l) for l in open("../results/sft/records.jsonl")]
rng = random.Random(5)
by = {}
for r in R:
    if r["target"] is not None: by.setdefault(r["cls"], []).append(r)
sel = [x for c in sorted(by) for x in rng.sample(by[c], n // len(by))]
eng = Engine(mode)
name = eng.merged or (list(eng.adapters)[0] if eng.adapters else None)
msgs = [S.build_messages_sft(r["evidence"]) for r in sel]
outs = []
for i in range(0, len(msgs), 8):
    outs += eng.generate(msgs[i:i + 8], 110, name)
ok = 0; per = {}
sw = {f"s{i}" for i in range(1, 10)}
for r, (t, ni, no) in zip(sel, outs):
    try:
        cand = S.parse_output(t); [parse_rule(d, sw) for d in cand]; v = True
    except Exception:
        v = False
    ok += v; per.setdefault(r["cls"], []).append(v)
print(mode, "valid", ok, "/", len(sel), {c: f"{sum(x)}/{len(x)}" for c, x in per.items()})
for r, (t, _, _) in list(zip(sel, outs))[:3]:
    print(r["cls"], t[:160])
