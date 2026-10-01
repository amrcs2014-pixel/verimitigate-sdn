"""Automated responders.

  none       detection only
  portdrop   R1: drop everything on the ingress port for 30 s (Swileh-style)
  template   R2: one classic template per class, no verification
  vtemplate  template ladder + verifier + twin (strong non-LLM baseline)
  llm        R3: LLM synthesis, retries only on controller rejection (unparseable/ill-formed)
  verimit    R4: VeriMitigate = LLM + verifier feedback (k=3) + twin replay + conservative fallback
Defenses (Paper B, any responder): provenance, threshold, costgate, hysteresis.
"""
import json, time, math
from collections import defaultdict, deque
import netsim as N
from netsim import Rule
import synth as S
from verifier import Verifier

INSTALL_S = 0.010        # flow-mod + barrier round trip per switch (modelled)
TWIN_REPLAY_S = 1.0      # accelerated replay window in the twin
VERIFY_CHARGE_S = 0.020  # charged per verifier invocation (95th percentile of measured cost)
STALE_S = 30.0
DET_MS_PER_REC = 0.02    # measured XGBoost inference cost per record (overwritten by runner)


class Responder:
    def __init__(self, kind, defenses=(), verifier_disabled=(), twin=True, k_retry=3, shots="all",
                 llm=None, tau_b=0.05, provisional=False, name=None, cex=True, prune=True,
                 prompt="fewshot", lat_scale=1.0):
        self.cex, self.prune, self.prompt = cex, prune, prompt
        self.lat_scale = lat_scale   # synthesis-latency scaling (sensitivity to faster accelerators)
        self.kind, self.defenses = kind, set(defenses)
        self.name = name or kind
        self.ver = Verifier(disabled=verifier_disabled, tau_b=tau_b)
        self.twin, self.k_retry, self.shots, self.llm = twin, k_retry, shots, llm
        self.provisional = provisional
        self.queue = []                  # pending incidents (dicts)
        self.busy_until = 0.0
        self.log = []
        self.c = defaultdict(float)
        self.install_times = defaultdict(deque)   # switch -> install timestamps (hysteresis budget)
        self.cooldown = {}                        # key -> time until which re-triggering is suppressed
        self.key_rules = defaultdict(list)
        self.inc_id = 0

    # ------------------------------------------------------------ alert intake
    def spoof_check(self, sim, alert):
        """Provenance: are the observed identifiers bound (warm-up binding table) to this ingress?"""
        loc = alert["loc"]
        for e, ip in alert["identities"][:10]:
            b = sim.net.binding.get(ip) if ip else None
            hm = sim.net.by_mac.get(e)
            if b is None and hm is None: return True
            if b is not None and (b[1], b[2]) != loc: return True
            if hm is not None and (hm.sw, hm.port) != loc: return True
        return False

    def covered(self, sim, alert, t, pending):
        sw, port = alert["loc"]
        hdr = dict(alert["hdr"] or {})
        e, ip = alert["identities"][0]
        if e is not None: hdr["eth_src"] = e
        if ip is not None and hdr.get("eth_type") == N.ETH_IP: hdr["ip_src"] = ip
        rules = [r for r in sim.net.rules if r.t_install <= t < r.t_expire] + [r for _, r in pending]
        r = sim.net.sec_table(sw, hdr, port, t, rules=rules, symbolic=True)
        return r is not None and r.owner == "responder"

    def on_window(self, sim, t, alerts):
        if self.kind == "none":
            self.c["alerts"] += len(alerts); return []
        out = []
        for a in alerts:
            self.c["alerts"] += 1
            key = (a["cls"], a["loc"])
            if self.covered(sim, a, t, sim.pending_installs):
                self.c["suppressed"] += 1; continue
            if "hysteresis" in self.defenses and self.cooldown.get(key, -1) > t:
                self.c["cooldown_suppressed"] += 1; continue
            spoof = self.spoof_check(sim, a)
            a["spoof_truth"] = any(tr != "Normal" for tr in a["true"]) and self.truth_spoof(sim, a)
            if "threshold" in self.defenses:
                need = 3 if a["prob"] < 0.995 else 2
                if a["windows"] < need:
                    self.c["held_threshold"] += 1; continue
            q = next((x for x in self.queue if x["key"] == key), None)
            if q is not None:
                idents = list(dict.fromkeys(q["identities"] + a["identities"]))
                q.update(identities=idents, windows=a["windows"], prob=max(q["prob"], a["prob"]))
                continue
            self.inc_id += 1
            inc = dict(id=self.inc_id, key=key, cls=a["cls"], loc=a["loc"], prob=a["prob"], windows=a["windows"],
                       identities=a["identities"], hdr=a["hdr"], t_alert=t, true=a["true"],
                       spoof_suspected=(spoof if "provenance" in self.defenses else None), spoof_flag=spoof,
                       spoof_truth=a["spoof_truth"])
            if a["cls"] == "Injection":
                inc["pktin"] = sim.pktin_load
            if a["cls"] == "Linkfab":
                es = a["identities"][0][0] or ""
                try:
                    _, s2, p2 = es.split(":"); inc["extra_locs"] = [(s2, int(p2))]
                except ValueError:
                    inc["extra_locs"] = []
            self.queue.append(inc)
            self.c["incidents"] += 1
            if all(tr == "Normal" for tr in a["true"]): self.c["fp_incidents"] += 1
            if self.provisional:
                out += self.provisional_rule(sim, inc, t)
        cur = max(t, self.busy_until)
        while self.queue and cur < t + 1.0:
            inc = self.queue.pop(0)
            if cur - inc["t_alert"] > STALE_S:
                self.c["stale"] += 1; continue
            rules, lat = self.process(sim, inc, t)
            lat["queue"] = cur - t
            dur = sum(v for k, v in lat.items() if k not in ("queue", "verify_meas", "twin_meas"))
            cur += dur
            for r in rules:
                r.t_install = cur; r.t_expire = cur + r.ttl
                out.append((r))
            inc["lat"] = lat; inc["t_done"] = cur; inc["n_rules"] = len(rules)
            self.log.append({k: v for k, v in inc.items() if k not in ("hdr",)})
        self.busy_until = cur
        return out

    def truth_spoof(self, sim, a):
        for e, ip in a["identities"][:3]:
            h = sim.net.by_ip.get(ip) if ip else None
            if h is not None and (h.sw, h.port) != a["loc"]: return True
            hm = sim.net.by_mac.get(e)
            if hm is not None and (hm.sw, hm.port) != a["loc"]: return True
            if h is None and hm is None: return True
        return False

    def provisional_rule(self, sim, inc, t):
        cand = S.conservative(inc)
        v = self.ver.check(sim, inc, cand, t)
        if v["ok"] and not v["noop"]:
            for r in v["rules"]: r.ttl = 30; r.tag = "provisional"; r.t_install = t + INSTALL_S; r.t_expire = r.t_install + 30
            return v["rules"]
        return []

    # ------------------------------------------------------------ processing
    def process(self, sim, inc, t):
        lat = defaultdict(float)
        lat["detect"] = DET_MS_PER_REC * 10 / 1e3
        k = self.kind
        inc["attempts"], inc["rejects"] = 0, []
        if k == "portdrop":
            cand = [{"match": {"in_port": inc["loc"][1]}, "action": "drop", "switches": [inc["loc"][0]], "priority": 100, "ttl": 30}]
            rules = self.materialize(sim, inc, cand, t)
            inc["outcome"] = "portdrop"
        elif k == "template":
            rules = self.materialize(sim, inc, S.template(inc, 0), t)
            inc["outcome"] = "template"
        elif k == "vtemplate":
            rules = None
            for rung, cand in enumerate(S.template(inc, None)):
                inc["attempts"] += 1
                cand = self.apply_defenses_to_candidate(sim, inc, cand)
                ok, res = self.verify_and_twin(sim, inc, cand, t, lat)
                if ok:
                    rules = [] if res["noop"] else res["rules"]
                    inc["outcome"] = "noop" if res["noop"] else ("fallback" if rung == len(S.template(inc, None)) - 1 else f"rung{rung}")
                    break
                inc["rejects"].append(res["check"])
            if rules is None:
                rules = []; inc["outcome"] = "none"
        elif k in ("llm", "verimit"):
            rules = self.llm_loop(sim, inc, t, lat, verified=(k == "verimit"))
        else:
            raise ValueError(k)
        rules = self.post_defenses(sim, inc, rules, t)
        lat["install"] = INSTALL_S * len({s for r in rules for s in r.switches}) if rules else 0.0
        for r in rules: r.incident = inc["id"]
        self.c["rules"] += len(rules)
        return rules, lat

    def shots_for(self, cls):
        if self.prompt == "sft": return []
        if self.shots == "all": return list(S.EXAMPLES)
        if self.shots == "none": return []
        if self.shots == "heldout":   # two examples of *other* classes only
            others = [c for c in S.EXAMPLES if c != cls]
            return others[:2]
        raise ValueError(self.shots)

    def llm_loop(self, sim, inc, t, lat, verified):
        sw = inc["loc"][0]
        installed = [r.as_json() for r in sim.net.rules if sw in r.switches or r.switches == ["*"]]
        ev = S.evidence(sim, inc, installed)
        msgs = S.build_messages_sft(ev) if self.prompt == "sft" else S.build_messages(ev, self.shots_for(inc["cls"]))
        for attempt in range(self.k_retry + 1):
            inc["attempts"] += 1
            resp = self.llm(msgs, 110)
            lat["synth"] += resp["latency"] * self.lat_scale
            self.c["llm_calls"] += 1
            text = resp["text"]
            try:
                cand = S.parse_output(text)
                cand = self.apply_defenses_to_candidate(sim, inc, cand)
            except (ValueError, json.JSONDecodeError) as e:
                inc["rejects"].append("syntax")
                fb = f"Your output was rejected by the controller: {e}. Reply with only a valid JSON array of rules."
                msgs = msgs + [{"role": "assistant", "content": text}, {"role": "user", "content": fb}]
                continue
            if not verified:
                # R3: the controller only rejects rules it cannot compile (schema / field domain errors)
                from verifier import parse_rule
                try:
                    parsed = [parse_rule(d, set(sim.topo.switches)) for d in cand]
                    ttl_ok = all(p["ttl"] > 0 for p in parsed)
                    if not ttl_ok: raise ValueError("ttl must be positive")
                except ValueError as e:
                    inc["rejects"].append("syntax")
                    fb = f"Your output was rejected by the controller: {e}. Reply with only a valid JSON array of rules."
                    msgs = msgs + [{"role": "assistant", "content": text}, {"role": "user", "content": fb}]
                    continue
                inc["outcome"] = f"llm_try{attempt}"
                return [Rule(p["match"], p["action"], p["switches"], priority=p["priority"], ttl=min(max(p["ttl"], 1), 3600),
                             rate_kbps=p["rate_kbps"], t_install=t) for p in parsed]
            ok, res = self.verify_and_twin(sim, inc, cand, t, lat)
            if ok:
                inc["outcome"] = "noop" if res["noop"] else f"llm_try{attempt}"
                return [] if res["noop"] else res["rules"]
            inc["rejects"].append(res["check"])
            fb = f"The verifier rejected these rules. Failed check: {res['check']}. Reason: {res['reason']}."
            if self.cex and res.get("cex"):
                fb += " Counterexample: " + json.dumps(res["cex"], separators=(",", ":"))
            fb += " Reply with only a corrected JSON array of rules."
            msgs = msgs + [{"role": "assistant", "content": text}, {"role": "user", "content": fb}]
        if not verified:
            inc["outcome"] = "none"; return []
        # conservative fallback (verified)
        cand = self.apply_defenses_to_candidate(sim, inc, S.conservative(inc))
        ok, res = self.verify_and_twin(sim, inc, cand, t, lat, twin=False)
        inc["outcome"] = "fallback" if ok else "none"
        return (res["rules"] if ok and not res["noop"] else [])

    def charge_verify(self, lat, res):
        """Charge a fixed verifier cost in the loop (keeps the simulation deterministic); the measured
        wall-clock time is recorded separately for reporting."""
        lat["verify"] += VERIFY_CHARGE_S
        lat["verify_meas"] += res.get("ms", 0.0) / 1e3

    def verify_and_twin(self, sim, inc, cand, t, lat, twin=None):
        res = self.ver.check(sim, inc, cand, t)
        self.charge_verify(lat, res)
        if not res["ok"] and self.prune and isinstance(cand, list) and len(cand) > 1:
            # verifier-guided pruning: drop rules that fail on their own (removing a rule never
            # widens blocking); the twin still checks that what remains stops the attack
            keep = []
            for c in cand:
                r1 = self.ver.check(sim, inc, [c], t)
                self.charge_verify(lat, r1)
                if r1["ok"]: keep.append(c)
            if keep and len(keep) < len(cand):
                r2 = self.ver.check(sim, inc, keep, t)
                self.charge_verify(lat, r2)
                if r2["ok"]:
                    self.c["pruned_rules"] += len(cand) - len(keep)
                    inc["pruned"] = inc.get("pruned", 0) + len(cand) - len(keep)
                    res = r2
        if not res["ok"]:
            self.c["rej_" + res["check"]] += 1
            return False, res
        if res["noop"]: return True, res
        if (self.twin if twin is None else twin):
            t0 = time.perf_counter()
            ok, why = self.twin_replay(sim, inc, res["rules"], t)
            lat["twin"] += TWIN_REPLAY_S                              # charged (deterministic)
            lat["twin_meas"] += time.perf_counter() - t0               # measured compute, reported only
            if not ok:
                self.c["rej_twin"] += 1
                res = dict(res, ok=False, check="twin", reason=why, cex=self._twin_cex)
                return False, res
        return True, res

    def twin_replay(self, sim, inc, rules, t):
        """Replay the last 5 s of recorded traffic against the candidate in a model of the network
        (the twin only knows detector labels, not ground truth)."""
        net = sim.net
        active = [r for r in net.rules if r.t_install <= t < r.t_expire]
        hyp = active + rules
        loc = inc["loc"]; susp = {e for e, _ in inc["identities"]} | {sim.net.by_name[n].mac for n in self.ver.suspects(sim, inc)}
        flagged_tot = flagged_blk = 0.0
        ben_tot = ben_lost = 0
        miss, hit = None, None
        pk = lambda l, h: dict({k: v for k, v in h.items() if v is not None}, in_port=l[1], switch=l[0])
        for (ts, kind, l, hdr, dmac, pred, vol, aid, kbps) in sim.history:
            if l == loc and pred == inc["cls"]:
                b0 = self._blocked(net, l, hdr, dmac, t, active, kbps)
                b1 = self._blocked(net, l, hdr, dmac, t, hyp, kbps)
                flagged_tot += vol; flagged_blk += vol * max(0.0, b1 - b0)
                if b1 - b0 < 0.5 and (miss is None or vol > miss[0]): miss = (vol, pk(l, hdr))
            elif kind == "benign" and pred == "Normal":
                if l == loc and hdr.get("eth_src") in susp: continue
                ben_tot += 1
                if self._blocked(net, l, hdr, dmac, t, hyp, kbps) > 0.5 and self._blocked(net, l, hdr, dmac, t, active, kbps) <= 0.5:
                    ben_lost += 1
                    if hit is None: hit = pk(l, hdr)
        self._twin_cex = None
        if flagged_tot > 0 and flagged_blk / flagged_tot < 0.5:
            self._twin_cex = {"flagged_packet_not_stopped": miss[1]} if miss else None
            return False, f"replay: candidate stops only {100 * flagged_blk / flagged_tot:.0f}% of the flagged traffic (need >= 50%)"
        if ben_tot > 0 and ben_lost / ben_tot > 0.02:
            self._twin_cex = {"benign_packet_dropped": hit} if hit else None
            return False, f"replay: candidate breaks {ben_lost} of {ben_tot} recent benign flows ({100 * ben_lost / ben_tot:.1f}% > 2%)"
        return True, None

    def _blocked(self, net, l, hdr, dmac, t, rules, kbps=0.0):
        """Fraction of this traffic the rules stop. A meter stops 1 - rate/offered of it, the same
        model the live network uses (small-frame floods and LLDP are barely touched by a meter)."""
        meter = lambda r: max(0.0, 1.0 - min(1.0, (r.rate_kbps or 0) / max(kbps, 1e-9)))
        if dmac is None:
            r = net.sec_table(l[0], hdr, l[1], t, rules=rules)
            if r is None: return 0.0
            return 1.0 if r.action in ("drop", "redirect") else (meter(r) if r.action == "meter" else 0.0)
        st, r, _ = net.deliver(l, hdr, dmac, t, rules=rules)
        if st in ("drop", "redirect"): return 1.0
        if st == "meter": return meter(r)
        return 0.0

    def materialize(self, sim, inc, cand, t):
        """Unverified install (R1/R2): the controller accepts anything that compiles."""
        from verifier import parse_rule
        cand = self.apply_defenses_to_candidate(sim, inc, cand)
        out = []
        for d in cand:
            try:
                p = parse_rule(d, set(sim.topo.switches))
            except ValueError:
                continue
            out.append(Rule(p["match"], p["action"], p["switches"], priority=p["priority"], ttl=max(p["ttl"], 1),
                            rate_kbps=p["rate_kbps"], t_install=t))
        return out

    # ------------------------------------------------------------ defenses
    def apply_defenses_to_candidate(self, sim, inc, cand):
        """Provenance-aware scoping: when identifiers are not bound to the evidence ingress,
        bind every rule to that ingress port and switch."""
        if "provenance" not in self.defenses or not inc.get("spoof_flag"):
            return cand
        sw, port = inc["loc"]
        out = []
        for d in cand:
            if not isinstance(d, dict) or not isinstance(d.get("match"), dict):
                out.append(d); continue
            d = json.loads(json.dumps(d))
            if inc["cls"] == "Linkfab":
                out.append(d); continue
            d["match"]["in_port"] = port
            d["switches"] = [sw]
            out.append(d)
        self.c["provenance_rewrites"] += 1
        return out

    def post_defenses(self, sim, inc, rules, t):
        if not rules: return rules
        if "costgate" in self.defenses:
            hv = {h.ip for h in sim.topo.hosts if h.role == "server"} | {h.mac for h in sim.topo.hosts if h.role == "server"}
            touches = any(v in hv for r in rules for v in r.match.values())
            if touches:
                if inc["windows"] < 5:
                    self.c["costgate_blocked"] += 1
                    inc["outcome"] = "costgate_deferred"
                    return []
                for r in rules: r.ttl = min(r.ttl, 30)
        if "hysteresis" in self.defenses:
            out = []
            for r in rules:
                r.ttl = max(r.ttl, 60)
                ok = True
                for s in r.switches:
                    dq = self.install_times[s]
                    while dq and dq[0] < t - 60: dq.popleft()
                    if len(dq) >= 6: ok = False
                if ok:
                    for s in r.switches: self.install_times[s].append(t)
                    out.append(r)
                else:
                    self.c["budget_blocked"] += 1
            if not out and rules:
                # budget exhausted: aggregate into one ingress-port meter (if verified safe)
                cand = S.conservative(inc)
                v = self.ver.check(sim, inc, cand, t)
                if v["ok"] and not v["noop"]:
                    out = v["rules"]; self.c["budget_aggregated"] += 1
            self.cooldown[inc["key"]] = t + max((r.ttl for r in out), default=0) + 30
            rules = out
        return rules

    def stats(self):
        return dict(self.c)
