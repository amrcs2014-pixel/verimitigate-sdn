"""On-policy preference pairs for DPO: the SFT synthesizer is sampled on training incidents
*inside the live simulation*; every sample is verified (verifier + twin) in situ; passing
responses are preferred over failing ones (verifier outcome = preference signal)."""
import os, json, random, sys
from collections import defaultdict
import scenarios as SC, sim as SM, synth as S
from responder import Responder
from llm_server import LLMClient
from sft_data import variants, specificity, TRAIN_TOPOS
from multiprocessing import Pool

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "results", "sft")
J = lambda x: json.dumps(x, separators=(",", ":"))
N_SAMPLES = 3


class PrefRecorder(Responder):
    def __init__(self, llm):
        super().__init__("vtemplate")
        self.llm, self.pairs, self.stats = llm, [], defaultdict(int)

    def process(self, sim, inc, t):
        lat = defaultdict(float)
        sw = inc["loc"][0]
        installed = [r.as_json() for r in sim.net.rules if sw in r.switches or r.switches == ["*"]]
        ev = S.evidence(sim, inc, installed)
        msgs = S.build_messages_sft(ev)
        outs = [self.llm(msgs, 160)["text"]] + [self.llm(msgs, 160, temperature=1.0, sample_id=k)["text"] for k in range(N_SAMPLES)]
        good, bad = [], []
        for txt in dict.fromkeys(outs):
            try:
                cand = S.parse_output(txt)
                ok, res = self.verify_and_twin(sim, inc, cand, t, lat)
            except Exception:
                ok, res = False, None
            (good if ok and not (res or {}).get("noop") else bad).append((txt, res))
        ladder = []
        for cand in variants(inc):
            ok, res = self.verify_and_twin(sim, inc, cand, t, lat)
            if ok and not res["noop"]: ladder.append((cand, res))
        chosen = good[0][0] if good else (J(max(ladder, key=lambda c: specificity(c[0]))[0]) if ladder else None)
        self.stats["incidents"] += 1; self.stats["greedy_ok"] += int(bool(good) and good[0][0] == outs[0])
        self.stats["any_ok"] += int(bool(good))
        if chosen is not None:
            for txt, _ in bad:
                self.pairs.append(dict(msgs=msgs, chosen=chosen, rejected=txt, cls=inc["cls"], source="on-policy"))
        rules = []
        if good: rules = good[0][1]["rules"]
        elif ladder: rules = max(ladder, key=lambda c: specificity(c[0]))[1]["rules"]
        lat["install"] = 0.01
        return rules, lat


def job(args):
    topo, cls, seed = args
    R = PrefRecorder(LLMClient("sft"))
    SM.Sim(topo, seed, SC.m0(topo, cls, seed), responder=R).run()
    return R.pairs, dict(R.stats)


def main():
    jobs = [(topo, cls, seed) for topo in TRAIN_TOPOS for cls in SC.CLASSES for seed in range(200, 206)]
    pairs, st = [], defaultdict(int)
    with Pool(16) as p:
        for i, (pp, s) in enumerate(p.imap_unordered(job, jobs)):
            pairs += pp
            for k, v in s.items(): st[k] += v
            if i % 20 == 0: print(i, len(jobs), len(pairs), dict(st), flush=True)
    with open(os.path.join(OUT, "dpo_onpolicy_pairs.jsonl"), "w") as f:
        for q in pairs: f.write(json.dumps(q) + "\n")
    # mix with seed (template-derived) pairs, balanced by class, capped
    seed_pairs = [json.loads(l) for l in open(os.path.join(OUT, "dpo_seed_pairs.jsonl"))]
    rng = random.Random(3)
    rng.shuffle(seed_pairs)
    by = defaultdict(list)
    for q in seed_pairs: by[q["cls"]].append(dict(q, source="template"))
    mix = pairs[:]
    for c, qs in by.items(): mix += qs[:40]
    rng.shuffle(mix)
    with open(os.path.join(OUT, "dpo_train.jsonl"), "w") as f:
        for q in mix[:500]: f.write(json.dumps(q) + "\n")
    json.dump(dict(st), open(os.path.join(OUT, "dpo_data_stats.json"), "w"))
    print("pairs", len(pairs), "mixed", min(len(mix), 500), dict(st))


if __name__ == "__main__":
    main()
