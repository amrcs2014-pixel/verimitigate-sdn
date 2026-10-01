"""Export topologies, sampled responder rule sets and the emulator's reachability predictions for the
Containernet validation. Predictions use the same data-plane walk as the verifier (static, no attack state)."""
import json, os, random
import analysis as A, netsim as N, sim as SM
from netsim import Rule
from verifier import Verifier

OUT = os.path.join(A.ROOT, "containernet")
TOPOS = ["linear", "tree", "star", "subnets", "iot"]          # loop-free (mesh needs STP)
RESP = ["portdrop", "template", "vtemplate", "llm", "verimit", "vtemplate_D", "verimit_D"]
PER_CELL = 3


def topo_json(name):
    t = N.build(name)
    return dict(name=name, switches=t.switches, links=[list(l) for l in t.links],
                hosts=[dict(name=h.name, ip=h.ip, mac=h.mac, sw=h.sw, port=h.port, role=h.role, service=h.service)
                       for h in t.hosts], shared=list(t.shared_port) if t.shared_port else None)


def pairs(sim):
    out = []
    for h in sim.topo.hosts:
        if h.role == "server": continue
        for svc, S in sim.topo.server_of.items():
            sh = N.SERVICES[svc]
            if h.role == "iot" and sh[4] == 0: continue
            if h.role == "client" and sh[3] == 0: continue
            out.append((h, S, svc))
    return out


def predict(topo, rules):
    sim = SM.Sim(topo, 0, [], responder=None)
    sim.net.refresh_view(0.0)
    R = [Rule(r["match"], r["action"], r["switches"], priority=100, ttl=10 ** 6, rate_kbps=r.get("rate_kbps", 1000),
              t_install=0.0) for r in rules]
    sim.net.rules = R
    v = Verifier()
    res = []
    for h, S, svc in pairs(sim):
        ok = v.pair_status(sim, R, h, S, svc, 0.0)
        res.append(dict(host=h.name, svc=svc, server=S.name, ip=S.ip, proto="tcp" if N.SERVICES[svc][0] == 6 else "udp",
                        port=N.SERVICES[svc][1], pred=bool(ok)))
    return res


def main():
    rng = random.Random(42)
    sets = []
    pool = []
    for grid, objs in [("A_main", None), ("B_main", ("O1", "O2", "O4"))]:
        for d in A.load(grid):
            if d["topo"] not in TOPOS or d["resp"] not in RESP or not d["rules"]: continue
            if objs and d["scen"] not in objs: continue
            pool.append((grid, d))
    lldp = 0
    for topo in TOPOS:
        for resp in RESP:
            for grid in ["A_main", "B_main"]:
                cand = [d for g, d in pool if g == grid and d["topo"] == topo and d["resp"] == resp]
                rng.shuffle(cand)
                k = 0
                for d in cand:
                    rules = [dict(match=r["match"], action=r["action"], switches=r["switches"]) for r in d["rules"]]
                    if any(r["match"].get("eth_type") == N.ETH_LLDP for r in rules):
                        lldp += 1; continue
                    sets.append(dict(id=f"{grid}:{d['id']}", grid=grid, topo=topo, resp=resp, scen=d["scen"],
                                     rules=rules, pred=predict(topo, rules)))
                    k += 1
                    if k == PER_CELL: break
    json.dump(dict(topologies={t: topo_json(t) for t in TOPOS}, sets=sets), open(os.path.join(OUT, "rulesets.json"), "w"))
    print(len(sets), "rule sets;", lldp, "skipped (LLDP rules)")
    print(sum(sum(1 for p in s["pred"] if not p["pred"]) for s in sets), "predicted-cut pairs of",
          sum(len(s["pred"]) for s in sets))


if __name__ == "__main__":
    main()
