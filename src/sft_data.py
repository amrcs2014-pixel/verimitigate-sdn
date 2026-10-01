"""Build the instruction set for the rule synthesizer from verifier-approved rules.

Runs the closed loop on the *training* topologies (linear, tree, star, mesh) with seeds
disjoint from evaluation seeds.  At every incident the template library is expanded into a
candidate set; each candidate is checked by the verifier and replayed in the twin *in the
live simulation state*; the most specific passing candidate becomes the target.  Failing
candidates yield repair dialogues (candidate -> verifier feedback with counterexample ->
approved rule) and are kept as rejected responses for preference optimisation.
"""
import sys, os, json, random, copy
import scenarios as SC, sim as SM, synth as S
from responder import Responder
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "results", "sft")
TRAIN_TOPOS = ["linear", "tree", "star", "mesh"]


def variants(inc):
    """Template library expanded with narrower variants (all candidates are then verified)."""
    base = S.template(inc, None)
    sw, port = inc["loc"]
    extra = []
    eth, ip = inc["identities"][0] if inc["identities"] else (None, None)
    if inc["cls"] in ("DDoS", "PortScan") and ip:
        extra.append([{"match": {"in_port": port, "eth_type": 2048, "ip_src": ip}, "action": "drop", "switches": [sw],
                       "priority": 100, "ttl": 300}])
        if eth:
            extra.append([{"match": {"in_port": port, "eth_src": eth}, "action": "drop", "switches": [sw],
                           "priority": 100, "ttl": 300}])
    if inc["cls"] == "Hijack" and eth:
        extra.append([{"match": {"in_port": port, "eth_src": eth, "eth_type": 2054}, "action": "drop", "switches": [sw],
                       "priority": 100, "ttl": 300}])
        extra.append([{"match": {"eth_src": eth}, "action": "drop", "switches": ["*"], "priority": 100, "ttl": 300}])
    return base + extra


def specificity(c):
    return (sum(len(r["match"]) for r in c) / max(len(c), 1), -sum(1 for r in c if r["switches"] == ["*"]),
            sum(1 for r in c if r["action"] == "drop"))


class Recorder(Responder):
    def __init__(self, sink, rng):
        super().__init__("vtemplate")
        self.sink, self.rng = sink, rng

    def process(self, sim, inc, t):
        from collections import defaultdict as dd
        lat = dd(float)
        sw = inc["loc"][0]
        installed = [r.as_json() for r in sim.net.rules if sw in r.switches or r.switches == ["*"]]
        ev = S.evidence(sim, inc, installed)
        results = []
        for cand in variants(inc):
            ok, res = self.verify_and_twin(sim, inc, cand, t, lat)
            results.append((cand, ok, res))
        passing = [(c, r) for c, ok, r in results if ok and not r["noop"]]
        failing = [(c, r) for c, ok, r in results if not ok]
        noop = any(ok and r["noop"] for c, ok, r in results)
        if passing:
            target, tres = max(passing, key=lambda cr: specificity(cr[0]))
            rules = tres["rules"]
        elif noop:
            target, rules = None, []
        else:
            target, rules = None, []
        rec = dict(topo=sim.topo.name, seed=sim.seed, cls=inc["cls"], true=inc["true"][:3], evidence=ev,
                   target=target, rejected=[dict(cand=c, check=r["check"], reason=r["reason"], cex=r.get("cex"))
                                            for c, r in failing])
        self.sink.append(rec)
        inc["outcome"] = "recorded"
        lat["install"] = 0.01
        return rules, lat


def main():
    os.makedirs(OUT, exist_ok=True)
    rng = random.Random(7)
    sink = []
    jobs = []
    for topo in TRAIN_TOPOS:
        for cls in SC.CLASSES:
            for seed in range(100, 140):
                jobs.append(("m0", topo, cls, seed))
        for pair in SC.M1_PAIRS:
            for seed in range(100, 110):
                jobs.append(("m1", topo, pair, seed))
    for i, (kind, topo, x, seed) in enumerate(jobs):
        atk = SC.m0(topo, x, seed) if kind == "m0" else SC.m1(topo, x, seed)
        R = Recorder(sink, rng)
        fp = 0.01 if seed % 4 == 0 else 0.0
        SM.Sim(topo, seed, atk, responder=R, fp_rate=fp).run()
        if i % 100 == 0: print(i, len(jobs), len(sink), flush=True)
    with open(os.path.join(OUT, "records.jsonl"), "w") as f:
        for r in sink: f.write(json.dumps(r) + "\n")
    cnt = defaultdict(int)
    for r in sink: cnt[(r["cls"], r["target"] is not None)] += 1
    print(dict(cnt))


if __name__ == "__main__":
    main()
