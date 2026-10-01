"""Closed-loop scenario engine: benign workload, attacks, trace-driven detection, metrics.

Every flow the simulator creates is paired with a *real* held-out LAN-SDN-NIDS record of
the matching class (and, for benign flows, matching protocol); the detector's decision for
that record is the LOTO XGBoost prediction on it.  Identifiers (ports, MACs, IPs) come from
the emulated network, so the evidence the responder sees is exactly what a controller-side
detector would see, including spoofed identifiers.
"""
import os, math, random, time, zlib
from collections import defaultdict, deque
import numpy as np, pandas as pd
import netsim as N
from netsim import ETH_IP, ETH_ARP, ETH_LLDP

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DET = os.path.join(ROOT, "results", "detector")
CLASSES = ["Normal", "Linkfab", "Injection", "Hijack", "DDoS", "PortScan"]
SIM2DS = {"linear": "Linear", "tree": "Tree", "star": "Star", "mesh": "Mesh", "subnets": "Subnets", "iot": "Subnets"}
REC_PER_WINDOW = {"DDoS": 3, "PortScan": 6, "Injection": 4, "Hijack": 2, "Linkfab": 1}
BYTES = {"dns": 300, "web": 50e3, "gw": 100e3, "mqtt": 2e3, "ssh": 20e3, "ftp": 1e6, "coap": 300, "rtp": 500e3}
_POOL_CACHE = {}


class RecordPool:
    """Held-out real records of one dataset topology with precomputed detector probabilities."""

    def __init__(self, ds_topo, variant="full"):
        key = (ds_topo, variant)
        if key not in _POOL_CACHE:
            cache = os.path.join(DET, f"pool_{ds_topo}.npz")
            if not os.path.exists(cache):
                idx = pd.read_parquet(os.path.join(DET, "record_index.parquet"))
                s_ = idx[idx.topology == ds_topo].reset_index(drop=True)
                np.savez(cache, label=np.array(s_.label.tolist(), dtype="U16"), layer=np.array(s_.last_layer.tolist(), dtype="U16"))
            z = np.load(cache)
            sub = pd.DataFrame({"label": z["label"], "last_layer": z["layer"]})
            P = np.load(os.path.join(DET, f"proba_{variant}_{ds_topo}.npy"))
            by_class = {c: np.where(sub.label.values == c)[0] for c in CLASSES}
            normal = sub.label.values == "Normal"
            by_layer = {}
            for svc, layers in N.SERVICE_LAYER.items():
                ix = np.where(normal & sub.last_layer.isin(layers).values)[0]
                by_layer[svc] = ix if len(ix) > 50 else by_class["Normal"]
            _POOL_CACHE[key] = (P, by_class, by_layer)
        self.P, self.by_class, self.by_layer = _POOL_CACHE[key]

    def draw(self, rng, cls=None, service=None):
        pool = self.by_layer[service] if service else self.by_class[cls]
        i = pool[rng.randrange(len(pool))]
        p = self.P[i]
        k = int(p.argmax())
        return i, CLASSES[k], float(p[k])


class Sim:
    def __init__(self, topo, seed, attacks, responder=None, horizon=120.0, dt=0.1, det_variant="full",
                 fp_rate=0.0, theta=0.9, flow_rate=0.4, warmup=20.0, min_recs=2, agg_s=10.0, stale_frac=0.0):
        self.rng = random.Random(seed)
        N.Rule._ids = __import__("itertools").count(1)   # rule ids restart per run (they appear in verifier feedback)
        self.seed = seed
        self.topo = N.build(topo, seed)
        self.net = N.Network(self.topo, self.rng)
        self.pool = RecordPool(SIM2DS[topo], det_variant)
        self.horizon, self.dt, self.theta, self.fp_rate = horizon, dt, theta, fp_rate
        self.flow_rate, self.warmup = flow_rate, warmup
        self.min_recs, self.agg_s = min_recs, agg_s
        self.flag_buf = defaultdict(deque)
        self.responder = responder
        self.attacks = attacks            # list of dicts, see scenarios.py
        self.attackers = {a for atk in attacks for a in atk["hosts"]}
        self.legit = [h for h in self.topo.hosts if h.name not in self.attackers]
        self.clients = [h for h in self.legit if h.role in ("client", "iot")]
        self.flows = []                   # benign flows
        self.m = defaultdict(float)       # scalar metrics
        self.series = defaultdict(list)
        self.pktin_load, self.victim_load = 0.0, defaultdict(float)
        self.window_records = []          # (loc, eth_src, ip_src, hdr, dst_mac, cls_true, pred, prob, volume)
        self.history = deque()            # recent traffic for the twin: (t, kind, loc, hdr, dst_mac, pred, vol, key)
        self.consec = defaultdict(int)    # consecutive alerted windows per incident key
        self.pending_installs = []        # (t_effective, Rule)
        self.events = []
        self.ttm = {}                     # attack id -> first time delivered fraction <= 0.5
        self.atk_off = defaultdict(float); self.atk_del = defaultdict(float)
        self.adv_pkts, self.adv_bytes = 0.0, 0.0
        self.host_down = defaultdict(float)   # legit host -> responder-attributable downtime (s)
        self.host_down_any = defaultdict(float)
        self.lost_bytes_rule, self.lost_bytes_any = 0.0, 0.0
        self.lost_by_rule, self.down_by_rule, self._rule_id = defaultdict(float), defaultdict(float), None
        self.hijack_victim_ok = {}
        self.inj_macs = defaultdict(deque)  # switch -> deque of expiry times of reactive entries
        for atk in attacks:
            atk.setdefault("id", atk["kind"] + ":" + ",".join(atk["hosts"]))
        if stale_frac > 0:
            # stale IP bindings (e.g. DHCP churn after warm-up): the binding table points to a wrong port
            srng = random.Random(seed * 7919 + 1)
            cl = [h for h in self.topo.hosts if h.role in ("client", "iot")]
            ports = sorted({(h.sw, h.port) for h in self.topo.hosts})
            for h in srng.sample(cl, int(round(stale_frac * len(cl)))):
                wrong = srng.choice([p for p in ports if p != (h.sw, h.port)])
                self.net.binding[h.ip] = (h.mac, wrong[0], wrong[1])

    # ------------------------------------------------------------------ helpers
    def H(self, name):
        return self.net.by_name[name]

    def loc(self, h):
        return (h.sw, h.port)

    def flow_hdr(self, src, dst, proto, tp_dst, tp_src, ip_src=None):
        return {"eth_src": src.mac, "eth_dst": dst.mac, "eth_type": ETH_IP, "ip_src": ip_src or src.ip,
                "ip_dst": dst.ip, "ip_proto": proto, "tp_src": tp_src, "tp_dst": tp_dst}

    def active(self, atk, t):
        if not (atk["start"] <= t < atk["end"]): return False
        if "period" in atk:    # oscillation: on for `on` seconds every `period`
            return (t - atk["start"]) % atk["period"] < atk["on"]
        return True

    def status_cause(self, st, rule, now):
        """Map a delivery status to (ok, cause) where cause is 'rule' (responder) or 'attack'."""
        if st in ("ok", "intercept"): return True, None
        if st in ("drop", "redirect") and rule is not None and rule.owner == "responder":
            self._rule_id = rule.id; return False, "rule"
        if st == "meter":
            self._rule_id = rule.id; return None, "rule"
        if st == "noroute" and self.net.link_lost_by:
            self._rule_id = next(iter(self.net.link_lost_by.values())); return False, "rule"
        return False, "attack"

    def meter_pass(self, rule, t):
        off = self.meter_offered.get(rule.id, 0.0)
        cap = rule.rate_kbps or 0
        if off <= 0: return 1.0 if cap >= 64 else 0.0
        return min(1.0, cap / off)

    # ------------------------------------------------------------------ benign traffic
    def new_flows(self, t):
        for h in self.clients:
            if self.rng.random() < self.flow_rate * self.dt:
                shares = [(s, v[3] if h.role == "client" else v[4]) for s, v in N.SERVICES.items()
                          if s in self.topo.server_of]
                if h.role == "client": shares.append(("rtp", 0.05))
                tot = sum(w for _, w in shares); r = self.rng.random() * tot
                for svc, w in shares:
                    r -= w
                    if r <= 0: break
                if svc == "rtp":
                    peers = [p for p in self.clients if p is not h and p.role == "client"]
                    dst, proto, port, dur = self.rng.choice(peers), 17, 5004, 10.0
                else:
                    dst = self.topo.server_of[svc]; proto, port, dur = N.SERVICES[svc][:3]
                f = dict(src=h, dst=dst, svc=svc, proto=proto, tp_dst=port, tp_src=self.rng.randint(32768, 60999),
                         t0=t, t1=t + dur, next_check=t, ok=True, cause=None, rec=None)
                ri, pred, prob = self.pool.draw(self.rng, service=svc)
                if self.fp_rate and self.rng.random() < self.fp_rate:
                    pred, prob = self.rng.choice(CLASSES[1:]), 0.95
                f["pred"], f["prob"] = pred, prob
                self.flows.append(f)
                hdr = self.flow_hdr(h, dst, proto, port, f["tp_src"])
                self.window_records.append((self.loc(h), h.mac, h.ip, hdr, dst.mac, "Normal", pred, prob, 1.0))
                self.history.append((t, "benign", self.loc(h), hdr, dst.mac, pred, 1.0, None, 100.0))
                # background control traffic of the host in the dataset's Normal mix (ARP ~16%, ICMP ~6%)
                for kind, p_emit in (("arp", 0.16 / 0.78), ("icmp", 0.06 / 0.78)):
                    if self.rng.random() < p_emit:
                        ri, pred, prob = self.pool.draw(self.rng, service=kind)
                        if self.fp_rate and self.rng.random() < self.fp_rate:
                            pred, prob = self.rng.choice(CLASSES[1:]), 0.95
                        if kind == "arp":
                            hh = {"eth_src": h.mac, "eth_dst": "ff:ff:ff:ff:ff:ff", "eth_type": ETH_ARP, "arp_op": 1}
                            dm = None
                        else:
                            hh = {"eth_src": h.mac, "eth_dst": dst.mac, "eth_type": ETH_IP, "ip_src": h.ip,
                                  "ip_dst": dst.ip, "ip_proto": 1}
                            dm = dst.mac
                        self.window_records.append((self.loc(h), h.mac, h.ip, hh, dm, "Normal", pred, prob, 1.0))
                        self.history.append((t, "benign", self.loc(h), hh, dm, pred, 1.0, None, 1.0))

    def check_pair(self, src, dst, hdr_fwd, hdr_rev, t, arp=False):
        """Bidirectional delivery incl. congestion; returns (ok, cause)."""
        net = self.net
        for (a, b, hdr) in ((src, dst, hdr_fwd), (dst, src, hdr_rev)):
            st, rule, path = net.deliver(self.loc(a), hdr, b.mac, t)
            ok, cause = self.status_cause(st, rule, t)
            if ok is None:   # metered by a responder rule
                if self.rng.random() > self.meter_pass(rule, t): return False, "rule"
            elif not ok:
                return False, cause
            if st == "divert": return False, "attack"
            if st == "intercept": self._intercepted = True
        if arp:
            for (a, b, op) in ((src, dst, 1), (dst, src, 2)):
                hdr = {"eth_src": a.mac, "eth_dst": b.mac, "eth_type": ETH_ARP, "arp_op": op}
                st, rule, _ = net.deliver(self.loc(a), hdr, b.mac, t)
                ok, cause = self.status_cause(st, rule, t)
                if ok is False: return False, cause
        for h in (src, dst):
            load = self.victim_load.get(h.name, 0.0)
            if load > N.HOST_BW and self.rng.random() > N.HOST_BW / load:
                return False, "attack"
        return True, None

    def run_flows(self, t):
        setup_p = min(1.0, N.PKTIN_CAP / max(self.pktin_load, 1e-9)) if self.pktin_load > N.PKTIN_CAP else 1.0
        live = []
        for f in self.flows:
            if f["ok"] is not True or t < f["next_check"]:
                if f["ok"] is True and t < f["t1"]: live.append(f)
                elif f["ok"] is True: self.finish(f)
                continue
            src, dst = f["src"], f["dst"]
            fwd = self.flow_hdr(src, dst, f["proto"], f["tp_dst"], f["tp_src"])
            rev = self.flow_hdr(dst, src, f["proto"], f["tp_src"], f["tp_dst"])
            first = f["next_check"] == f["t0"]
            if first:
                sw = src.sw
                occ = len(self.inj_macs[sw]) + len(self.net.rules_on(sw, t))
                p = setup_p * (min(1.0, N.TABLE_CAP / occ) if occ > N.TABLE_CAP else 1.0)
                if self.rng.random() > p:
                    f["ok"], f["cause"] = False, "attack"; self.finish(f); continue
            self._intercepted = False
            ok, cause = self.check_pair(src, dst, fwd, rev, t, arp=first)
            if cause == "rule": f["rule_id"] = self._rule_id
            if self._intercepted and not f.get("icpt"):
                f["icpt"] = True
                if f["t0"] >= self.win0: self.m["intercepted_win"] += 1
            if not ok:
                f["ok"], f["cause"] = False, cause; self.finish(f); continue
            f["next_check"] = min(f["t1"], t + 1.0) if t < f["t1"] else f["t1"] + 1
            if t >= f["t1"]:
                self.finish(f)
            else:
                live.append(f)
        self.flows = live

    def finish(self, f):
        if f.get("done"): return
        f["done"] = True
        w = "win" if f["t0"] >= self.win0 else "pre"
        self.m[f"flows_{w}"] += 1
        if not f["ok"]:
            self.m[f"fail_{w}"] += 1
            self.m[f"fail_{w}_{f['cause']}"] += 1
            b = BYTES.get(f["svc"], 1e3)
            self.lost_bytes_any += b
            if f["cause"] == "rule":
                self.lost_bytes_rule += b
                self.lost_by_rule[f.get("rule_id")] += b

    # ------------------------------------------------------------------ attacks
    def run_attacks(self, t):
        net = self.net
        self.pktin_load = self.flow_rate * len(self.clients)   # benign new-flow Packet-Ins
        self.victim_load = defaultdict(float)
        self.meter_offered = defaultdict(float)
        # prune injected reactive entries
        for sw, dq in self.inj_macs.items():
            while dq and dq[0] <= t: dq.popleft()
        for atk in self.attacks:
            if not self.active(atk, t): continue
            kind = atk["kind"]
            off_w, del_w = 0.0, 0.0
            for hn in atk["hosts"]:
                A = self.H(hn); L = self.loc(A)
                if kind == "Linkfab":
                    # relayed LLDP claiming the peer attacker's switch port
                    peer = self.H([x for x in atk["hosts"] if x != hn][0])
                    hdr = {"eth_type": ETH_LLDP, "eth_src": "lldp:%s:%d" % (peer.sw, peer.port), "eth_dst": "01:80:c2:00:00:0e"}
                    r = net.sec_table(A.sw, hdr, A.port, t)
                    passed = 0.0 if (r is not None and r.action in ("drop", "redirect")) else 1.0
                    off_w += 1; del_w += passed
                    self.atk_hdr = hdr
                    fl = (peer.sw, peer.port, A.sw, A.port)
                    if passed and (t % N.LLDP_PERIOD) < self.dt:
                        net.links[fl] = t; net.fake_links.add(fl)
                    self.record_attack(t, atk, A, hdr, None, "Linkfab", 1.0, rec_scale=1.0 / N.LLDP_PERIOD, kbps=0.0)
                    continue
                spoof_ip = atk.get("spoof_ip")
                if atk.get("rotate"):
                    k = int(t // atk["rotate"])
                    spoof_ip = "10.0.%d.%d" % (100 + (k * 7 + zlib.crc32(hn.encode()) % 5) % 50, (k * 13) % 250 + 1)
                if kind in ("DDoS", "Spoof-DDoS"):
                    V = self.H(atk["target"])
                    hdr = self.flow_hdr(A, V, 6, 80, self.rng.randint(1024, 65535), ip_src=spoof_ip)
                    hdr_rep = dict(hdr); hdr_rep["tp_src"] = None
                    rate = atk.get("mbps", 40.0)
                    st, r, _ = net.deliver(L, hdr, V.mac, t)
                    frac = self.frac(st, r, rate * 1000, t)
                    self.victim_load[V.name] += rate * frac
                    off_w += rate; del_w += rate * frac
                    pps = rate * 1e6 / 8 / 1000
                    self.record_attack(t, atk, A, hdr_rep, V.mac, "DDoS", pps, kbps=rate * 1000)
                elif kind in ("PortScan", "Spoof-PortScan"):
                    tgt = self.rng.choice([h for h in self.topo.hosts if h is not A])
                    hdr = self.flow_hdr(A, tgt, 6, self.rng.randint(1, 1024), self.rng.randint(1024, 65535), ip_src=spoof_ip)
                    pps = atk.get("pps", 200.0)
                    st, r, _ = net.deliver(L, hdr, tgt.mac, t)
                    frac = self.frac(st, r, pps * 0.5, t)
                    off_w += pps; del_w += pps * frac
                    hrep = dict(hdr); hrep["tp_dst"] = None; hrep["tp_src"] = None; hrep["ip_dst"] = None; hrep["eth_dst"] = None
                    self.record_attack(t, atk, A, hrep, tgt.mac, "PortScan", pps, kbps=pps * 0.5)
                elif kind == "Injection":
                    fps = atk.get("fps", 300.0)
                    fake = N.mac(5000 + self.rng.randrange(60000))
                    fip = "10.0.%d.%d" % (200 + self.rng.randrange(50), self.rng.randrange(1, 250))
                    hdr = {"eth_src": fake, "eth_dst": "ff:ff:ff:ff:ff:ff", "eth_type": ETH_ARP, "arp_op": 1}
                    hrep = dict(hdr); hrep["eth_src"] = None
                    r = net.sec_table(A.sw, hdr, A.port, t)
                    frac = self.frac_rule(r, fps * 0.5, t)
                    self.pktin_load += fps * frac
                    dq = self.inj_macs[A.sw]
                    for _ in range(int(fps * frac * self.dt)): dq.append(t + N.REACTIVE_IDLE)
                    off_w += fps; del_w += fps * frac
                    self.record_attack(t, atk, A, hrep, None, "Injection", fps, eth_src=fake, ip_src=fip, kbps=fps * 0.5)
                elif kind == "Hijack":
                    V = self.H(atk["victim"])
                    fps = atk.get("fps", 20.0)
                    hdr = {"eth_src": V.mac, "eth_dst": "ff:ff:ff:ff:ff:ff", "eth_type": ETH_ARP, "arp_op": 2}
                    r = net.sec_table(A.sw, hdr, A.port, t)
                    frac = self.frac_rule(r, fps * 0.5, t)
                    off_w += fps; del_w += fps * frac
                    va = sum(1 for f in self.flows if f["src"] is V or f["dst"] is V) * 10 + 1.0
                    pa = fps * frac / (fps * frac + va)
                    if self.rng.random() < pa * self.dt * 10:
                        net.host_table[V.mac] = L
                    elif self.rng.random() < (1 - pa) * self.dt * 10:
                        net.host_table[V.mac] = self.loc(V)
                    self.record_attack(t, atk, A, hdr, None, "Hijack", fps, ip_src=V.ip, kbps=fps * 0.5)
            self.atk_off[atk["id"]] += off_w * self.dt
            self.atk_del[atk["id"]] += del_w * self.dt
            if atk["kind"].startswith("Spoof"):
                pk = (atk.get("mbps", 0) * 1e6 / 8 / 1000 if "DDoS" in atk["kind"] else atk.get("pps", 200.0)) * len(atk["hosts"])
                self.adv_pkts += pk * self.dt
                self.adv_bytes += pk * self.dt * (1000 if "DDoS" in atk["kind"] else 60)
            if off_w > 0 and atk["id"] not in self.ttm and del_w / off_w <= 0.5:
                self.ttm[atk["id"]] = t - atk["start"]
        # victims recover location when hijack stops being delivered
        for atk in self.attacks:
            if atk["kind"] == "Hijack" and not self.active(atk, t):
                V = self.H(atk["victim"]); self.net.host_table[V.mac] = self.loc(V)
        # expire fake links once no longer refreshed
        for fl in list(self.net.fake_links):
            if t - self.net.links.get(fl, -1e9) > N.LINK_TIMEOUT:
                self.net.fake_links.discard(fl); self.net.links.pop(fl, None)

    def frac(self, st, rule, offered_kbps, t):
        if st in ("drop", "redirect"): return 0.0
        if st == "meter":
            self.meter_offered[rule.id] += offered_kbps
            return min(1.0, (rule.rate_kbps or 0) / max(offered_kbps, 1e-9))
        return 1.0

    def frac_rule(self, r, offered, t):
        if r is None: return 1.0
        if r.action in ("drop", "redirect"): return 0.0
        if r.action == "meter": return min(1.0, (r.rate_kbps or 0) / max(offered, 1e-9))
        return 1.0

    def record_attack(self, t, atk, A, hdr, dst_mac, cls, rate, rec_scale=1.0, eth_src=None, ip_src=None, kbps=0.0):
        """Emit real held-out records of class `cls` for detection windows (sampled per tick)."""
        n = REC_PER_WINDOW[cls] * rec_scale * self.dt
        if atk["kind"].startswith("Spoof"):
            n *= atk.get("rec_mult", 1.0)
        k = int(n) + (1 if self.rng.random() < n - int(n) else 0)
        es = eth_src or hdr.get("eth_src"); ips = ip_src or hdr.get("ip_src")
        for _ in range(k):
            ri, pred, prob = self.pool.draw(self.rng, cls=cls)
            self.window_records.append((self.loc(A), es, ips, hdr, dst_mac, cls, pred, prob, rate))
        self.history.append((t, "attack", self.loc(A), hdr, dst_mac, cls, rate, atk["id"], kbps))

    # ------------------------------------------------------------------ detection
    def detect(self, t):
        """Alert aggregation: a (class, ingress) key raises an alert in this window when it has a
        flagged record now and at least MIN_RECS flagged records within the last AGG_S seconds."""
        groups = defaultdict(list)
        for rec in self.window_records:
            loc, es, ips, hdr, dmac, true, pred, prob, vol = rec
            if pred != "Normal" and prob >= self.theta:
                groups[(pred, loc)].append(rec)
                self.flag_buf[(pred, loc)].append(t)
        self.window_records = []
        for k, dq in self.flag_buf.items():
            while dq and dq[0] <= t - self.agg_s: dq.popleft()
        alerts = []
        seen = set()
        for (cls, loc), recs in groups.items():
            key = (cls, loc)
            if len(self.flag_buf[key]) < self.min_recs:
                self.m["sub_threshold_windows"] += 1
                continue
            seen.add(key)
            self.consec[key] += 1
            idents = {}
            for r in recs: idents[(r[1], r[2])] = idents.get((r[1], r[2]), 0) + 1
            tgt = defaultdict(float)
            for r in recs:
                h = r[3]
                tgt[(h.get("ip_dst"), h.get("ip_proto"), h.get("tp_dst"))] += 1
            alerts.append(dict(cls=cls, loc=loc, prob=float(np.mean([r[7] for r in recs])), n=len(recs),
                               identities=sorted(idents, key=lambda k: -idents[k]),
                               hdr=recs[0][3], dst_mac=recs[0][4], true=[r[5] for r in recs],
                               windows=self.consec[key], t=t))
        for key in list(self.consec):
            if key not in seen: self.consec[key] = 0
        while self.history and self.history[0][0] < t - 5.0:
            self.history.popleft()
        return alerts

    # ------------------------------------------------------------------ probes & downtime
    def probes(self, t):
        for svc in N.PROTECTED:
            S = self.topo.server_of.get(svc)
            if S is None: continue
            for _ in range(3):
                h = self.rng.choice(self.clients)
                ok, cause = self.check_pair(h, S, self.flow_hdr(h, S, N.SERVICES[svc][0], N.SERVICES[svc][1], 40000),
                                            self.flow_hdr(S, h, N.SERVICES[svc][0], 40000, N.SERVICES[svc][1]), t, arp=True)
                w = "win" if t >= self.win0 else "pre"
                self.m[f"probe_{w}"] += 1
                if ok: self.m[f"probe_ok_{w}"] += 1
                elif cause == "rule": self.m[f"probe_fail_rule_{w}"] += 1
        # per-legit-host connectivity to DNS (downtime accounting, Paper B)
        dns = self.topo.server_of["dns"]
        for h in self.clients:
            ok, cause = self.check_pair(h, dns, self.flow_hdr(h, dns, 17, 53, 40000), self.flow_hdr(dns, h, 17, 40000, 53), t, arp=True)
            if not ok:
                self.host_down_any[h.name] += 1.0
                if cause == "rule":
                    self.host_down[h.name] += 1.0
                    self.down_by_rule[self._rule_id] += 1.0

    # ------------------------------------------------------------------ main loop
    def run(self):
        t, net = 0.0, self.net
        self.win0 = min(a["start"] for a in self.attacks) if self.attacks else self.warmup
        net.refresh_view(t)
        steps = int(round(self.horizon / self.dt))
        for i in range(steps):
            t = round(i * self.dt, 6)
            gone = net.expire(t)
            for r in gone: self.events.append((t, "expire", r.id))
            while self.pending_installs and self.pending_installs[0][0] <= t:
                _, r = self.pending_installs.pop(0)
                net.install(r); self.events.append((t, "install", r.id))
            if (t % N.LLDP_PERIOD) < self.dt / 2:
                net.lldp_tick(t)
            net.refresh_view(t)
            if abs(t - round(t)) < 1e-6 and t > 0:
                # the 1-s window (t-1, t] has closed: classify its records, then respond
                self.probes(t)
                alerts = self.detect(t)
                if self.responder is not None and t >= self.warmup:
                    for rule in self.responder.on_window(self, t, alerts):
                        self.pending_installs.append((rule.t_install, rule))
                    self.pending_installs.sort(key=lambda x: x[0])
            self.run_attacks(t)
            net.refresh_view(t)
            self.new_flows(t)
            self.run_flows(t)
            self.series["rules"].append(len(net.rules))
        for f in self.flows: self.finish(f)
        return self.summary()

    def summary(self):
        m = dict(self.m)
        fw = max(m.get("flows_win", 0), 1)
        out = dict(
            benign_flows=m.get("flows_win", 0),
            benign_fail=m.get("fail_win", 0) / fw,
            intercepted=m.get("intercepted_win", 0) / fw,
            collateral=m.get("fail_win_rule", 0) / fw,
            attack_fail=m.get("fail_win_attack", 0) / fw,
            prot_avail=m.get("probe_ok_win", 0) / max(m.get("probe_win", 0), 1),
            prot_fail_rule=m.get("probe_fail_rule_win", 0) / max(m.get("probe_win", 0), 1),
            rules_installed=len(self.net.rule_log),
            rules_max=max(self.series["rules"]) if self.series["rules"] else 0,
            rules_end=len(self.net.rules),
            host_down_rule=sum(self.host_down.values()),
            host_down_any=sum(self.host_down_any.values()),
            lost_bytes_rule=self.lost_bytes_rule,
            adv_pkts=self.adv_pkts, adv_bytes=self.adv_bytes,
        )
        res = {}
        for atk in self.attacks:
            off = self.atk_off[atk["id"]]
            res[atk["id"]] = dict(residual=self.atk_del[atk["id"]] / off if off else None,
                                  ttm=self.ttm.get(atk["id"]))
        out["attacks"] = res
        # attribute responder harm to the incident that caused each rule: incidents triggered only by
        # benign records (detector false positives) vs incidents triggered by attack/adversary traffic
        inc_true = {}
        if self.responder is not None:
            for inc in getattr(self.responder, "log", []):
                inc_true[inc.get("id")] = any(tr != "Normal" for tr in inc.get("true", []))
        rule_adv = {r.id: inc_true.get(r.incident, True) for r in self.net.rule_log}
        out["lost_bytes_rule_adv"] = sum(v for k, v in self.lost_by_rule.items() if rule_adv.get(k, True))
        out["lost_bytes_rule_fp"] = sum(v for k, v in self.lost_by_rule.items() if not rule_adv.get(k, True))
        out["host_down_rule_adv"] = sum(v for k, v in self.down_by_rule.items() if rule_adv.get(k, True))
        out["host_down_rule_fp"] = sum(v for k, v in self.down_by_rule.items() if not rule_adv.get(k, True))
        out["events"] = len(self.events)
        return out
