"""Scenario builders for Paper A (M0, M1, M4) and Paper B (O1-O4)."""
import random, zlib
import netsim as N

TOPOS = ["linear", "tree", "star", "mesh", "subnets", "iot"]
CLASSES = ["DDoS", "PortScan", "Injection", "Hijack", "Linkfab"]
START, END, HORIZON = 30.0, 90.0, 120.0


def stable_seed(*parts):
    """Process-independent seed (the built-in hash is salted per process)."""
    return zlib.crc32(repr(parts).encode()) & 0xffffffff


def _clients(topo):
    return [h for h in topo.hosts if h.role in ("client", "iot")]


def pick(topo, rng, n, distinct_switch=True, exclude=()):
    cs = [h for h in _clients(topo) if h.name not in exclude]
    rng.shuffle(cs)
    out, used = [], set()
    for h in cs:
        if distinct_switch and h.sw in used: continue
        out.append(h); used.add(h.sw)
        if len(out) == n: return out
    for h in cs:
        if h not in out: out.append(h)
        if len(out) == n: break
    return out


def attack(topo, cls, rng, start=START, end=END, exclude=()):
    if cls == "DDoS":
        A = pick(topo, rng, 3, exclude=exclude)
        tgt = "web" if "web" in topo.server_of else "mqtt"
        return dict(kind="DDoS", hosts=[a.name for a in A], target=tgt, mbps=60.0, start=start, end=end)
    if cls == "PortScan":
        A = pick(topo, rng, 1, exclude=exclude)
        return dict(kind="PortScan", hosts=[A[0].name], pps=200.0, start=start, end=end)
    if cls == "Injection":
        A = pick(topo, rng, 1, exclude=exclude)
        return dict(kind="Injection", hosts=[A[0].name], fps=300.0, start=start, end=end)
    if cls == "Hijack":
        A, V = pick(topo, rng, 2, exclude=exclude)
        return dict(kind="Hijack", hosts=[A.name], victim=V.name, fps=20.0, start=start, end=end)
    if cls == "Linkfab":
        # two colluding hosts on the two most distant switches
        import networkx as nx
        G = nx.Graph(); G.add_edges_from((u, v) for u, _, v, _ in topo.links)
        d = dict(nx.all_pairs_shortest_path_length(G))
        pairs = sorted(((d[a][b], a, b) for a in G for b in G if a < b), reverse=True)
        far = [p for p in pairs if p[0] == pairs[0][0]]
        _, s1, s2 = rng.choice(far)
        c1 = [h for h in _clients(topo) if h.sw == s1 and h.name not in exclude]
        c2 = [h for h in _clients(topo) if h.sw == s2 and h.name not in exclude]
        if not c1 or not c2:
            A = pick(topo, rng, 2, exclude=exclude); c1, c2 = [A[0]], [A[1]]
        return dict(kind="Linkfab", hosts=[rng.choice(c1).name, rng.choice(c2).name], start=start, end=end)
    raise ValueError(cls)


def m0(topo_name, cls, seed):
    topo = N.build(topo_name)
    rng = random.Random(stable_seed(topo_name, cls, seed))
    return [attack(topo, cls, rng)]


M1_PAIRS = [("DDoS", "Hijack"), ("PortScan", "Linkfab"), ("Injection", "DDoS")]


def m1(topo_name, pair, seed):
    topo = N.build(topo_name)
    rng = random.Random(stable_seed(topo_name, tuple(pair), seed, "m1"))
    a1 = attack(topo, pair[0], rng, start=30, end=90)
    a2 = attack(topo, pair[1], rng, start=45, end=100, exclude=a1["hosts"] + [a1.get("victim", "")])
    return [a1, a2]


# ------------------------------------------------------------------ Paper B
BUDGET = {"low": dict(mbps=5.0, pps=50.0, rec_mult=0.5), "med": dict(mbps=20.0, pps=200.0, rec_mult=1.0),
          "high": dict(mbps=60.0, pps=800.0, rec_mult=2.0)}


def adversary(topo_name, objective, budget, seed):
    """O1 collateral induction, O2 protected-service isolation, O3 responder exhaustion, O4 oscillation.
    The adversary controls one compromised host and spoofs ip_src (directly controllable field)."""
    topo = N.build(topo_name)
    rng = random.Random(stable_seed(topo_name, objective, budget, seed, "B"))
    A = pick(topo, rng, 1)[0]
    b = BUDGET[budget]
    base = dict(kind="Spoof-PortScan" if rng.random() < 0.5 else "Spoof-DDoS", hosts=[A.name],
                start=START, end=END, mbps=b["mbps"], pps=b["pps"], rec_mult=b["rec_mult"])
    if base["kind"] == "Spoof-DDoS":
        base["target"] = "web" if "web" in topo.server_of else "mqtt"
    if objective == "O1":
        V = pick(topo, rng, 1, exclude=[A.name])[0]
        return [dict(base, spoof_ip=V.ip, victim=V.name)]
    if objective == "O2":
        svc = rng.choice([s for s in N.PROTECTED if s in topo.server_of])
        return [dict(base, spoof_ip=topo.server_of[svc].ip, victim=svc)]
    if objective == "O3":
        genuine = attack(topo, "DDoS", rng, start=50.0, end=END, exclude=[A.name])
        return [dict(base, rotate=1.0), genuine]
    if objective == "O4":
        V = pick(topo, rng, 1, exclude=[A.name])[0]
        return [dict(base, spoof_ip=V.ip, victim=V.name, period=40.0, on=6.0, end=HORIZON)]
    raise ValueError(objective)
