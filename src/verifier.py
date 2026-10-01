"""Deterministic pre-deployment verifier for candidate mitigation rules.

Checks (in order): syntax/schema (incl. OpenFlow match prerequisites and class semantics),
TTL sanity, scope sanity, conflict (firewall-anomaly classes of Al-Shaer & Hamed),
reachability of protected services (bidirectional, incl. ARP, and control-plane aware:
a rule that suppresses LLDP on an inter-switch port removes that link from the
controller's view before paths are recomputed), and blast radius over all legitimate
(host, service) pairs.

Reachability is exact for this grammar: rules are conjunctions of exact-match fields,
so every legitimate (host, service) pair is one header equivalence class except for the
ephemeral source port, which is kept symbolic (a rule constraining it is treated as
matching - a conservative choice).
"""
import time, copy
import networkx as nx
import netsim as N
from netsim import Rule, ETH_IP, ETH_ARP, ETH_LLDP

ACTIONS = {"drop", "meter", "redirect"}
TTL_CAP = 600
TAU_B = 0.05
METER_MIN_KBPS = 64
CHECKS = ("syntax", "ttl", "scope", "conflict", "reachability", "blast")
INT_FIELDS = {"in_port", "eth_type", "ip_proto", "tp_src", "tp_dst", "arp_op"}


def _norm_value(k, v):
    if k in INT_FIELDS:
        if isinstance(v, str):
            v = v.strip().lower()
            return int(v, 16) if v.startswith("0x") else int(v)
        return int(v)
    return str(v).lower()


def parse_rule(d, switches):
    """Normalise one candidate rule dict; raise ValueError with a field-level reason."""
    if not isinstance(d, dict): raise ValueError("rule is not a JSON object")
    m = d.get("match")
    if not isinstance(m, dict) or not m: raise ValueError("'match' must be a non-empty object")
    match = {}
    for k, v in m.items():
        if k not in N.FIELDS: raise ValueError(f"unknown match field '{k}' (allowed: {', '.join(N.FIELDS)})")
        if v in ("*", None, ""): continue      # wildcard == omit
        try:
            match[k] = _norm_value(k, v)
        except Exception:
            raise ValueError(f"bad value for '{k}': {v!r}")
    if not match: raise ValueError("match has only wildcards")
    act = str(d.get("action", "")).lower()
    if act not in ACTIONS: raise ValueError(f"action must be one of {sorted(ACTIONS)}")
    rate = d.get("rate_kbps")
    if act == "meter":
        try: rate = int(rate)
        except Exception: raise ValueError("meter requires integer 'rate_kbps'")
        if rate <= 0: raise ValueError("rate_kbps must be > 0")
    sw = d.get("switches", [])
    if isinstance(sw, str): sw = [sw]
    if sw in (["all"], ["*"], "all"): sw = ["*"]
    sw = [str(s).lower() for s in sw]
    if not sw: raise ValueError("'switches' must list at least one switch")
    for s in sw:
        if s != "*" and s not in switches: raise ValueError(f"unknown switch '{s}'")
    try: ttl = int(d.get("ttl", 0))
    except Exception: raise ValueError("ttl must be an integer")
    try: prio = int(d.get("priority", 100))
    except Exception: raise ValueError("priority must be an integer")
    return dict(match=match, action=act, rate_kbps=rate, switches=sw, ttl=ttl, priority=prio)


def prereq_errors(m):
    """OpenFlow 1.3 match prerequisites."""
    if any(k in m for k in ("ip_src", "ip_dst", "ip_proto")) and m.get("eth_type") != ETH_IP:
        return "ip_src/ip_dst/ip_proto require eth_type=0x0800"
    if any(k in m for k in ("tp_src", "tp_dst")) and m.get("ip_proto") not in (6, 17):
        return "tp_src/tp_dst require ip_proto 6 or 17"
    if "arp_op" in m and m.get("eth_type") != ETH_ARP:
        return "arp_op requires eth_type=0x0806"
    return None


def class_semantics(cls, m, act):
    """Wildcards allowed only where the class semantics allow them."""
    if cls == "Hijack" and "eth_src" not in m:
        return "a Hijack response must match the hijacked eth_src (it may not be wildcarded)"
    if cls == "Linkfab" and "in_port" not in m:
        return "a Linkfab response must be bound to the in_port(s) injecting LLDP"
    if cls == "Injection" and "in_port" not in m:
        return "an Injection response must be bound to the in_port of the injecting host"
    if cls in ("DDoS", "PortScan") and not ({"ip_src", "in_port", "eth_src"} & set(m)):
        return f"a {cls} response must identify the source (ip_src, eth_src or in_port)"
    return None


def overlap(a, b):
    return all(a[k] == b[k] for k in set(a) & set(b))


def covers(general, specific):
    """general's match set contains specific's (every constraint of general is in specific)."""
    return all(k in specific and specific[k] == v for k, v in general.items())


class Verifier:
    def __init__(self, disabled=(), tau_b=TAU_B):
        self.disabled, self.tau_b = set(disabled), tau_b

    # --------------------------------------------------------------- helpers
    def suspects(self, sim, inc):
        """Hosts responsible for the evidence traffic.  On a single-host access port the attached
        host is the only possible physical source (whatever identifiers it claims); on a shared
        port only hosts whose MAC appears in the evidence are suspects."""
        sw, port = inc["loc"]
        on_port = [h for h in sim.topo.hosts if h.sw == sw and h.port == port and h.role != "server"]
        if len(on_port) == 1:
            return {on_port[0].name}
        ids = {e for e, _ in inc["identities"]}
        return {h.name for h in on_port if h.mac in ids}

    def pairs(self, sim, exclude):
        out = []
        for h in sim.topo.hosts:
            if h.role == "server" or h.name in exclude: continue
            for svc, S in sim.topo.server_of.items():
                sh = N.SERVICES[svc]
                if h.role == "iot" and sh[4] == 0: continue
                if h.role == "client" and sh[3] == 0: continue
                out.append((h, S, svc))
        return out

    def pair_status(self, sim, rules, h, S, svc, now):
        net = sim.net
        proto, port = N.SERVICES[svc][:2]
        fwd = sim.flow_hdr(h, S, proto, port, None)
        rev = sim.flow_hdr(S, h, proto, None, port)
        arpq = {"eth_src": h.mac, "eth_dst": S.mac, "eth_type": ETH_ARP, "arp_op": 1}
        arpr = {"eth_src": S.mac, "eth_dst": h.mac, "eth_type": ETH_ARP, "arp_op": 2}
        for a, b, hdr in ((h, S, fwd), (S, h, rev), (h, S, arpq), (S, h, arpr)):
            st, r, path = net.deliver((a.sw, a.port), hdr, b.mac, now, rules=rules, symbolic=True)
            bad = st in ("drop", "redirect", "noroute", "divert") or (st == "meter" and (r.rate_kbps or 0) < METER_MIN_KBPS)
            if bad:
                self._last = dict(src=a.name, dst=b.name, ingress=f"{a.sw}:{a.port}",
                                  packet={k: v for k, v in hdr.items() if v is not None},
                                  outcome=st, at_switch=(path[-1] if path else None),
                                  rule=(r.as_json() if r is not None else None))
                return False
        return True

    def hypothetical_view(self, sim, rules, now):
        """Directed inter-switch links whose LLDP would be suppressed by `rules`."""
        lost = []
        for (u, pu, v, pv) in sim.net.links:
            if (u, pu, v, pv) in sim.net.fake_links: continue
            hdr = {"eth_type": ETH_LLDP, "eth_src": "lldp:%s:%d" % (u, pu), "eth_dst": "01:80:c2:00:00:0e"}
            r = sim.net.sec_table(v, hdr, pv, now, rules=rules)
            if r is not None and r.action in ("drop", "redirect"):
                lost.append((u, v))
        return lost

    # --------------------------------------------------------------- main
    def check(self, sim, inc, cand_dicts, now):
        """Return dict(ok, reason, check, rules(list[Rule]), noop, timings, warnings)."""
        t0 = time.perf_counter()
        res = dict(ok=False, reason=None, check=None, rules=[], noop=False, warnings=[], per_check={})
        switches = set(sim.topo.switches)
        parsed = []

        def fail(check, reason):
            res.update(ok=False, check=check, reason=reason)
            res["ms"] = (time.perf_counter() - t0) * 1e3
            return res

        # 1. syntax / schema
        if not cand_dicts: return fail("syntax", "no rule produced")
        for d in cand_dicts:
            try:
                p = parse_rule(d, switches)
            except ValueError as e:
                return fail("syntax", str(e))
            if "syntax" not in self.disabled:
                e = prereq_errors(p["match"]) or class_semantics(inc["cls"], p["match"], p["action"])
                if e: return fail("syntax", e)
            parsed.append(p)
        # 2. TTL
        if "ttl" not in self.disabled:
            for p in parsed:
                if p["ttl"] <= 0: return fail("ttl", "drop/meter/redirect rules must carry a positive ttl")
                if p["ttl"] > TTL_CAP: return fail("ttl", f"ttl {p['ttl']} exceeds cap {TTL_CAP}")
        # 3. scope sanity
        if "scope" not in self.disabled:
            allowed = {inc["loc"][0]} | {l[0] for l in inc.get("extra_locs", [])}
            for p in parsed:
                sw = set(p["switches"])
                if "*" in sw or not sw <= allowed:
                    return fail("scope", f"rule must be scoped to the evidence switch(es) {sorted(allowed)}, got {p['switches']}")
        rules = [Rule(p["match"], p["action"], p["switches"], priority=p["priority"], ttl=max(p["ttl"], 1),
                      rate_kbps=p["rate_kbps"], t_install=now, incident=inc["id"]) for p in parsed]
        res["rules"] = rules
        active = [r for r in sim.net.rules if r.t_install <= now < r.t_expire]
        # 4. conflict
        if "conflict" not in self.disabled:
            n_red = 0
            for c in rules:
                for r in active:
                    if not (set(c.switches) & set(r.switches) or "*" in c.switches or "*" in r.switches): continue
                    if not overlap(c.match, r.match): continue
                    if covers(r.match, c.match) and r.priority >= c.priority:
                        if r.action == c.action: n_red += 1; continue
                        return fail("conflict", f"shadowed by installed rule #{r.id} {r.as_json()} (priority {r.priority})")
                    if covers(c.match, r.match) and c.priority > r.priority and r.action != c.action:
                        res["warnings"].append(f"generalizes rule #{r.id}")
                    elif r.action != c.action:
                        res["warnings"].append(f"correlated with rule #{r.id}")
            if n_red == len(rules):
                res.update(ok=True, noop=True, reason="redundant: already covered by installed rules")
                res["ms"] = (time.perf_counter() - t0) * 1e3
                return res
        need_reach = "reachability" not in self.disabled
        need_blast = "blast" not in self.disabled
        if need_reach or need_blast:
            hyp = active + rules
            lost = self.hypothetical_view(sim, hyp, now)
            base_lost = self.hypothetical_view(sim, active, now)
            net = sim.net
            saved = (net.D, net._path_cache)
            D0 = net.D
            D1 = D0.copy(); D1.remove_edges_from([e for e in lost if D1.has_edge(*e)])
            D0b = D0.copy(); D0b.remove_edges_from([e for e in base_lost if D0b.has_edge(*e)])
            susp = self.suspects(sim, inc)
            pairs = self.pairs(sim, susp)
            try:
                net.D, net._path_cache = D0b, {}
                base = [self.pair_status(sim, active, h, S, s, now) for h, S, s in pairs]
                net.D, net._path_cache = D1, {}
                new = [self.pair_status(sim, hyp, h, S, s, now) for h, S, s in pairs]
            finally:
                net.D, net._path_cache = saved
            cut = [(h.name, s) for (h, S, s), b, n in zip(pairs, base, new) if b and not n]
            prot_first = sorted(cut, key=lambda c: c[1] not in N.PROTECTED)
            cex = {}
            if cut:
                try:
                    net.D, net._path_cache = D1, {}
                    hh = sim.net.by_name[prot_first[0][0]]
                    self.pair_status(sim, hyp, hh, sim.topo.server_of[prot_first[0][1]], prot_first[0][1], now)
                    cex = dict(self._last)
                finally:
                    net.D, net._path_cache = saved
                if lost: cex["lldp_links_lost"] = [f"{u}-{v}" for u, v in lost[:3]]
            res["cex"] = cex
            prot_cut = [c for c in cut if c[1] in N.PROTECTED]
            res["per_check"]["cut_pairs"] = len(cut); res["per_check"]["pairs"] = len(pairs)
            if need_reach and prot_cut:
                ex = prot_cut[0]
                return fail("reachability", f"rule cuts protected service '{ex[1]}' for legitimate host {ex[0]} "
                                            f"({len(prot_cut)} protected (host,service) pairs cut)")
            if need_blast and len(cut) > self.tau_b * max(len(pairs), 1):
                return fail("blast", f"blast radius {len(cut)}/{len(pairs)} legitimate (host,service) pairs "
                                     f"({100 * len(cut) / len(pairs):.1f}%) exceeds {100 * self.tau_b:.0f}%")
        res.update(ok=True)
        res["ms"] = (time.perf_counter() - t0) * 1e3
        return res
