"""Experiment runner for Paper A (VeriMitigate) and Paper B (responder robustness).

  python run_exp.py <grid> [--workers N]
Results are appended to results/<grid>.jsonl (resumable: finished task ids are skipped).
"""
import os, sys, json, time, argparse, hashlib, traceback
from multiprocessing import Pool
import scenarios as SC

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(ROOT, "results")
SEEDS = range(5)

# ------------------------------------------------------------------ responder configurations
RESP = {
    "none": dict(kind="none"),
    "portdrop": dict(kind="portdrop"),
    "template": dict(kind="template"),
    "vtemplate": dict(kind="vtemplate"),
    "llm": dict(kind="llm", adapter="sft", prompt="sft"),                 # R3: same synthesizer, no verifier
    "verimit": dict(kind="verimit", adapter="sft", prompt="sft"),         # R4: VeriMitigate
    # ablations (Paper A)
    "vm_no_conflict": dict(kind="verimit", adapter="sft", prompt="sft", verifier_disabled=["conflict"]),
    "vm_no_reach": dict(kind="verimit", adapter="sft", prompt="sft", verifier_disabled=["reachability"]),
    "vm_no_blast": dict(kind="verimit", adapter="sft", prompt="sft", verifier_disabled=["blast"]),
    "vm_no_scope": dict(kind="verimit", adapter="sft", prompt="sft", verifier_disabled=["scope"]),
    "vm_no_ttl": dict(kind="verimit", adapter="sft", prompt="sft", verifier_disabled=["ttl"]),
    "vm_no_semantics": dict(kind="verimit", adapter="sft", prompt="sft", verifier_disabled=["syntax"]),
    "vm_no_twin": dict(kind="verimit", adapter="sft", prompt="sft", twin=False),
    "vm_no_cex": dict(kind="verimit", adapter="sft", prompt="sft", cex=False),
    "vm_no_prune": dict(kind="verimit", adapter="sft", prompt="sft", prune=False),
    "vm_dpo": dict(kind="verimit", adapter="dpo3", prompt="sft"),         # A5: SFT + DPO (verifier-labelled preferences)
    "vm_dpo2": dict(kind="verimit", adapter="dpo2", prompt="sft"),
    "vm_sft_val": dict(kind="verimit", adapter="sft", prompt="sft"),
    "vm_base_fewshot": dict(kind="verimit", adapter=None, prompt="fewshot", shots="all"),   # A4: no fine-tuning
    "vm_base_zeroshot": dict(kind="verimit", adapter=None, prompt="fewshot", shots="none"),
    "llm_base_fewshot": dict(kind="llm", adapter=None, prompt="fewshot", shots="all"),
    "vm_provisional": dict(kind="verimit", adapter="sft", prompt="sft", provisional=True),
    # Paper B
    "vm_speed2": dict(kind="verimit", adapter="sft", prompt="sft", lat_scale=0.5),
    "vm_speed5": dict(kind="verimit", adapter="sft", prompt="sft", lat_scale=0.2),
    "vm_speed10": dict(kind="verimit", adapter="sft", prompt="sft", lat_scale=0.1),
    "vm_speed20": dict(kind="verimit", adapter="sft", prompt="sft", lat_scale=0.05),
    "verimit_D": dict(kind="verimit", adapter="sft", prompt="sft", defenses=["provenance", "threshold", "costgate", "hysteresis"]),
    "vtemplate_D": dict(kind="vtemplate", defenses=["provenance", "threshold", "costgate", "hysteresis"]),
    "vt_prov": dict(kind="vtemplate", defenses=["provenance"]),
    "vt_thr": dict(kind="vtemplate", defenses=["threshold"]),
    "vt_cost": dict(kind="vtemplate", defenses=["costgate"]),
    "vt_hyst": dict(kind="vtemplate", defenses=["hysteresis"]),
    "vm_prov": dict(kind="verimit", adapter="sft", prompt="sft", defenses=["provenance"]),
    "vm_thr": dict(kind="verimit", adapter="sft", prompt="sft", defenses=["threshold"]),
    "vm_cost": dict(kind="verimit", adapter="sft", prompt="sft", defenses=["costgate"]),
    "vm_hyst": dict(kind="verimit", adapter="sft", prompt="sft", defenses=["hysteresis"]),
}


def tid(d):
    return hashlib.md5(json.dumps(d, sort_keys=True).encode()).hexdigest()[:16]


# ------------------------------------------------------------------ grids
def grid(name):
    T = []
    if name == "A_main":
        for r in ["none", "portdrop", "template", "vtemplate", "llm", "verimit"]:
            for topo in SC.TOPOS:
                for cls in SC.CLASSES:
                    for s in SEEDS:
                        T.append(dict(grid=name, scen="M0", topo=topo, cls=cls, seed=s, resp=r))
    elif name == "A_m1":
        for r in ["none", "portdrop", "template", "vtemplate", "llm", "verimit"]:
            for topo in SC.TOPOS:
                for pair in SC.M1_PAIRS:
                    for s in SEEDS:
                        T.append(dict(grid=name, scen="M1", topo=topo, cls="+".join(pair), seed=s, resp=r))
    elif name == "A_m4":
        for r in ["portdrop", "template", "vtemplate", "llm", "verimit", "vtemplate_D", "verimit_D"]:
            for fp in [0.02, 0.05, 0.10]:
                for topo in SC.TOPOS:
                    for cls in SC.CLASSES:
                        for s in range(2):
                            T.append(dict(grid=name, scen="M4", topo=topo, cls=cls, seed=s, resp=r, fp=fp))
    elif name == "A_abl":
        for r in ["vm_no_conflict", "vm_no_reach", "vm_no_blast", "vm_no_scope", "vm_no_ttl", "vm_no_semantics",
                  "vm_no_twin", "vm_no_cex", "vm_no_prune", "vm_dpo", "vm_base_fewshot", "vm_base_zeroshot",
                  "llm_base_fewshot", "vm_provisional"]:
            for topo in SC.TOPOS:
                for cls in SC.CLASSES:
                    for s in SEEDS:
                        T.append(dict(grid=name, scen="M0", topo=topo, cls=cls, seed=s, resp=r))
    elif name == "A_det":   # A6: detector with data-plane features only
        for r in ["vtemplate", "verimit"]:
            for topo in SC.TOPOS:
                for cls in SC.CLASSES:
                    for s in range(3):
                        T.append(dict(grid=name, scen="M0", topo=topo, cls=cls, seed=s, resp=r, det="dataplane"))
    elif name == "B_main":
        for r in ["portdrop", "template", "vtemplate", "vtemplate_D", "llm", "verimit", "verimit_D"]:
            for obj in ["O1", "O2", "O3", "O4"]:
                for b in ["low", "med", "high"]:
                    for topo in SC.TOPOS:
                        for s in SEEDS:
                            T.append(dict(grid=name, scen=obj, topo=topo, budget=b, seed=s, resp=r))
    elif name == "B_none":
        for obj in ["O1", "O2", "O3", "O4"]:
            for b in ["low", "med", "high"]:
                for topo in SC.TOPOS:
                    for s in SEEDS:
                        T.append(dict(grid=name, scen=obj, topo=topo, budget=b, seed=s, resp="none"))
    elif name == "B_abl":
        for r in ["vm_prov", "vm_thr", "vm_cost", "vm_hyst"]:
            for obj in ["O1", "O2", "O3", "O4"]:
                for topo in SC.TOPOS:
                    for s in range(3):
                        T.append(dict(grid=name, scen=obj, topo=topo, budget="med", seed=s, resp=r))
    elif name == "B_cost":   # defense cost under genuine attacks (Paper A M0 with defenses on)
        for r in ["verimit_D", "vtemplate_D"]:
            for topo in SC.TOPOS:
                for cls in SC.CLASSES:
                    for s in SEEDS:
                        T.append(dict(grid=name, scen="M0", topo=topo, cls=cls, seed=s, resp=r))
    elif name == "A_val":    # synthesizer selection on TRAINING topologies, fresh seeds (not used for any reported result)
        for r in ["vm_sft_val", "vm_dpo2", "vm_dpo"]:
            for topo in ["linear", "tree", "star", "mesh"]:
                for cls in SC.CLASSES:
                    for s in range(300, 303):
                        T.append(dict(grid=name, scen="M0", topo=topo, cls=cls, seed=s, resp=r))
    elif name == "A_speed":   # sensitivity of TTM/residual to synthesis speed (faster accelerators)
        for r in ["vm_speed2", "vm_speed5", "vm_speed10", "vm_speed20"]:
            for topo in SC.TOPOS:
                for cls in SC.CLASSES:
                    for s in range(3):
                        T.append(dict(grid=name, scen="M0", topo=topo, cls=cls, seed=s, resp=r))
    elif name == "B_abl_t":   # single defenses on the (abusable) verified template ladder, all budgets
        for r in ["vt_prov", "vt_thr", "vt_cost", "vt_hyst"]:
            for obj in ["O1", "O2", "O3", "O4"]:
                for b in ["low", "med", "high"]:
                    for topo in SC.TOPOS:
                        for s in SEEDS:
                            T.append(dict(grid=name, scen=obj, topo=topo, budget=b, seed=s, resp=r))
    elif name == "B_stale":   # sensitivity of D1 provenance scoping to stale bindings
        for st in [0.1, 0.3]:
            for r in ["vtemplate_D"]:
                for obj in ["O1", "O2", "O3", "O4"]:
                    for topo in SC.TOPOS:
                        for s in SEEDS:
                            T.append(dict(grid=name, scen=obj, topo=topo, budget="med", seed=s, resp=r, stale=st))
                for topo in SC.TOPOS:
                    for cls in SC.CLASSES:
                        for s in SEEDS:
                            T.append(dict(grid=name, scen="M0", topo=topo, cls=cls, seed=s, resp=r, stale=st))
    else:
        raise ValueError(name)
    for t in T: t["id"] = tid(t)
    return T


# ------------------------------------------------------------------ worker
_llm = {}


def work(task):
    import sim as SM, responder as RP
    from llm_server import LLMClient
    try:
        cfg = dict(RESP[task["resp"]])
        kind = cfg.pop("kind"); adapter = cfg.pop("adapter", None)
        llm = None
        if kind in ("llm", "verimit"):
            if adapter not in _llm: _llm[adapter] = LLMClient(adapter)
            llm = _llm[adapter]
        R = RP.Responder(kind, llm=llm, name=task["resp"], **cfg)
        if task["scen"] == "M0": atk = SC.m0(task["topo"], task["cls"], task["seed"])
        elif task["scen"] == "M1": atk = SC.m1(task["topo"], tuple(task["cls"].split("+")), task["seed"])
        elif task["scen"] == "M4": atk = SC.m0(task["topo"], task["cls"], task["seed"])
        else: atk = SC.adversary(task["topo"], task["scen"], task["budget"], task["seed"])
        t0 = time.time()
        sim = SM.Sim(task["topo"], task["seed"], atk, responder=R, fp_rate=task.get("fp", 0.0),
                     det_variant=task.get("det", "full"), stale_frac=task.get("stale", 0.0))
        out = sim.run()
        incs = []
        for inc in R.log:
            incs.append(dict(cls=inc["cls"], true=inc["true"][:4], t_alert=inc["t_alert"], t_done=inc.get("t_done"),
                             outcome=inc.get("outcome"), attempts=inc.get("attempts"), rejects=inc.get("rejects"),
                             n_rules=inc.get("n_rules"), lat=inc.get("lat"), spoof_flag=inc.get("spoof_flag"),
                             spoof_truth=inc.get("spoof_truth"), windows=inc.get("windows"), pruned=inc.get("pruned", 0)))
        rules = [dict(t=r.t_install, ttl=r.ttl, action=r.action, match=r.match, switches=r.switches, tag=r.tag)
                 for r in sim.net.rule_log]
        return dict(task, out=out, rstats=R.stats(), incidents=incs, rules=rules[:200],
                    victim=[a.get("victim") for a in atk], atk=[{k: v for k, v in a.items()} for a in atk],
                    wall=time.time() - t0)
    except Exception:
        return dict(task, error=traceback.format_exc())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("grid")
    ap.add_argument("--workers", type=int, default=10)
    ap.add_argument("--only", default="")
    ap.add_argument("--maxseed", type=int, default=10**9)
    a = ap.parse_args()
    T = grid(a.grid)
    if a.only: T = [t for t in T if t["resp"] in a.only.split(",")]
    T = [t for t in T if t["seed"] < a.maxseed]
    path = os.path.join(RES, a.grid + ".jsonl")
    done = set()
    if os.path.exists(path):
        for l in open(path):
            try:
                d = json.loads(l)
                if "error" not in d: done.add(d["id"])
            except Exception: pass
    todo = [t for t in T if t["id"] not in done]
    # interleave LLM and non-LLM tasks so the LLM server always has concurrent requests
    print(f"{a.grid}: {len(T)} tasks, {len(todo)} to run", flush=True)
    t0 = time.time(); n = 0; err = 0
    with Pool(a.workers) as pool, open(path, "a") as f:
        for res in pool.imap_unordered(work, todo, chunksize=1):
            f.write(json.dumps(res) + "\n"); f.flush(); n += 1
            if "error" in res:
                err += 1
                if err <= 3: print(res["error"], flush=True)
            if n % 25 == 0:
                el = time.time() - t0
                print(f"{n}/{len(todo)} {el:.0f}s eta {el / n * (len(todo) - n):.0f}s errors={err}", flush=True)
    print("done", a.grid, n, "errors", err, time.time() - t0)


if __name__ == "__main__":
    main()
