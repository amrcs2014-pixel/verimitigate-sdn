"""Assemble class-balanced SFT examples (first-turn + repair dialogues) and DPO seed pairs."""
import json, random, os, collections
import synth as S
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
D = os.path.join(ROOT, "results", "sft")
rng = random.Random(11)
R = [json.loads(l) for l in open(os.path.join(D, "records.jsonl"))]
R = [r for r in R if r["target"] is not None]
by = collections.defaultdict(list)
for r in R: by[r["cls"]].append(r)
CAP = 330
sel = []
for c, rs in by.items():
    rng.shuffle(rs); sel += rs[:CAP]
rng.shuffle(sel)
J = lambda x: json.dumps(x, separators=(",", ":"))
ex, pairs = [], []
for r in sel:
    msgs = S.build_messages_sft(r["evidence"])
    ex.append(dict(msgs=msgs, target=J(r["target"]), cls=r["cls"], kind="first"))
    for rej in r["rejected"]:
        pairs.append(dict(msgs=msgs, chosen=J(r["target"]), rejected=J(rej["cand"]), cls=r["cls"], check=rej["check"]))
    if r["rejected"] and rng.random() < 0.35:
        rej = rng.choice(r["rejected"])
        fb = f"The verifier rejected these rules. Failed check: {rej['check']}. Reason: {rej['reason']}."
        if rej.get("cex"): fb += " Counterexample: " + J(rej["cex"])
        fb += " Reply with only a corrected JSON array of rules."
        m2 = msgs + [{"role": "assistant", "content": J(rej["cand"])}, {"role": "user", "content": fb}]
        ex.append(dict(msgs=m2, target=J(r["target"]), cls=r["cls"], kind="repair"))
rng.shuffle(ex)
with open(os.path.join(D, "sft_train.jsonl"), "w") as f:
    for e in ex: f.write(json.dumps(e) + "\n")
with open(os.path.join(D, "dpo_seed_pairs.jsonl"), "w") as f:
    for p in pairs: f.write(json.dumps(p) + "\n")
print(len(ex), collections.Counter((e["cls"], e["kind"]) for e in ex), len(pairs))
