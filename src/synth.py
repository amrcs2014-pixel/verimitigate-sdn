"""Rule synthesizers: LLM (few-shot, verifier-feedback retries), templates, template ladder."""
import json, re, time
import netsim as N

SYSTEM = (
    "You are the mitigation module of an SDN controller. Given an intrusion incident detected in the network, "
    "write OpenFlow table-0 mitigation rules. Reply with ONLY a JSON array of rules, no prose.\n"
    "Rule schema: {\"match\":{<field>:<value>,...},\"action\":\"drop\"|\"meter\"|\"redirect\","
    "\"rate_kbps\":<int, meter only>,\"switches\":[<switch ids>],\"priority\":<int>,\"ttl\":<seconds>}\n"
    "Match fields: in_port, eth_src, eth_dst, eth_type, ip_src, ip_dst, ip_proto, tp_src, tp_dst, arp_op. "
    "Omitted fields are wildcards. OpenFlow prerequisites: ip_src/ip_dst/ip_proto need eth_type 2048; "
    "tp_src/tp_dst need ip_proto 6 or 17; arp_op needs eth_type 2054; LLDP frames have eth_type 35020.\n"
    "Goals: stop the attack traffic; keep every protected service and every other host reachable; "
    "use the narrowest match that works; ttl must be between 1 and 600."
)

# One worked example per class, on topologies/identifiers distinct from the test networks.
EXAMPLES = {
    "DDoS": ({"class": "DDoS", "confidence": 0.99, "switch": "s7", "in_port": 3,
              "sources": [{"eth_src": "00:00:00:00:01:11", "ip_src": "10.1.0.17"}],
              "frame": {"eth_type": 2048, "ip_proto": 6},
              "targets": [{"ip_dst": "10.1.9.2", "ip_proto": 6, "tp_dst": 80}], "hosts_on_port": 1,
              "installed_rules": [], "protected": [{"service": "dns", "ip": "10.1.9.1"}]},
             [{"match": {"in_port": 3, "eth_type": 2048, "ip_src": "10.1.0.17"}, "action": "drop",
               "switches": ["s7"], "priority": 100, "ttl": 300}]),
    "PortScan": ({"class": "PortScan", "confidence": 0.97, "switch": "s6", "in_port": 2,
                  "sources": [{"eth_src": "00:00:00:00:01:22", "ip_src": "10.1.0.34"}],
                  "frame": {"eth_type": 2048, "ip_proto": 6},
                  "targets": [{"ip_dst": "many", "ip_proto": 6, "tp_dst": "many"}], "hosts_on_port": 1,
                  "installed_rules": [], "protected": [{"service": "dns", "ip": "10.1.9.1"}]},
                 [{"match": {"in_port": 2, "eth_type": 2048, "ip_src": "10.1.0.34"}, "action": "drop",
                   "switches": ["s6"], "priority": 100, "ttl": 300}]),
    "Injection": ({"class": "Injection", "confidence": 0.95, "switch": "s9", "in_port": 5,
                   "sources": [{"eth_src": "00:00:00:00:9a:01", "ip_src": "10.1.203.7"},
                               {"eth_src": "00:00:00:00:b3:44", "ip_src": "10.1.211.90"}],
                   "n_distinct_sources": 37, "frame": {"eth_type": 2054, "arp_op": 1}, "packet_in_rate_port": 290.0, "hosts_on_port": 1,
                   "installed_rules": [], "protected": [{"service": "dns", "ip": "10.1.9.1"}]},
                  [{"match": {"in_port": 5}, "action": "drop", "switches": ["s9"], "priority": 100, "ttl": 180}]),
    "Hijack": ({"class": "Hijack", "confidence": 0.99, "switch": "s8", "in_port": 4,
                "sources": [{"eth_src": "00:00:00:00:01:05", "ip_src": "10.1.0.6"}],
                "frame": {"eth_type": 2054, "arp_op": 2},
                "note": "eth_src 00:00:00:00:01:05 was previously located at s5 port 1", "hosts_on_port": 1,
                "installed_rules": [], "protected": [{"service": "dns", "ip": "10.1.9.1"}]},
               [{"match": {"in_port": 4, "eth_src": "00:00:00:00:01:05"}, "action": "drop", "switches": ["s8"],
                 "priority": 100, "ttl": 300}]),
    "Linkfab": ({"class": "Linkfab", "confidence": 0.93, "switch": "s5", "in_port": 6,
                 "frame": {"eth_type": 35020}, "lldp_claimed_peer": {"switch": "s2", "in_port": 7}, "hosts_on_port": 1,
                 "installed_rules": [], "protected": [{"service": "dns", "ip": "10.1.9.1"}]},
                [{"match": {"in_port": 6, "eth_type": 35020}, "action": "drop", "switches": ["s5"], "priority": 100, "ttl": 300},
                 {"match": {"in_port": 7, "eth_type": 35020}, "action": "drop", "switches": ["s2"], "priority": 100, "ttl": 300}]),
}


def evidence(sim, inc, installed_on_sw):
    sw, port = inc["loc"]
    ev = {"class": inc["cls"], "confidence": round(inc["prob"], 3), "switch": sw, "in_port": port}
    ids = inc["identities"][:3]
    ev["sources"] = [{"eth_src": e, "ip_src": i} for e, i in ids]
    if len(inc["identities"]) > 1: ev["n_distinct_sources"] = len(inc["identities"])
    h = inc.get("hdr") or {}
    ev["frame"] = {k: h[k] for k in ("eth_type", "ip_proto", "arp_op") if h.get(k) is not None}
    if inc["cls"] in ("DDoS", "PortScan") and h.get("ip_dst") is not None:
        ev["targets"] = [{"ip_dst": h.get("ip_dst"), "ip_proto": h.get("ip_proto"), "tp_dst": h.get("tp_dst")}]
    elif inc["cls"] == "PortScan":
        ev["targets"] = [{"ip_dst": "many", "ip_proto": 6, "tp_dst": "many"}]
    if inc["cls"] == "Injection":
        ev["packet_in_rate_port"] = round(inc.get("pktin", 0.0), 1)
    if inc["cls"] == "Linkfab" and inc.get("extra_locs"):
        s2, p2 = inc["extra_locs"][0]
        ev["lldp_claimed_peer"] = {"switch": s2, "in_port": p2}
    if inc["cls"] == "Hijack":
        for e, _ in ids:
            hh = sim.net.by_mac.get(e)
            if hh is not None and (hh.sw, hh.port) != inc["loc"]:
                ev["note"] = f"eth_src {e} was previously located at {hh.sw} port {hh.port}"
    ev["hosts_on_port"] = sum(1 for x in sim.topo.hosts if (x.sw, x.port) == inc["loc"])
    if inc.get("spoof_suspected") is not None:
        ev["spoof_suspected"] = inc["spoof_suspected"]
    ev["installed_rules"] = installed_on_sw[:4]
    ev["protected"] = [{"service": s, "ip": sim.topo.server_of[s].ip} for s in N.PROTECTED if s in sim.topo.server_of]
    return ev


def build_messages(ev, shots):
    msgs = [{"role": "system", "content": SYSTEM}]
    for cls in shots:
        e, r = EXAMPLES[cls]
        msgs.append({"role": "user", "content": "Incident: " + json.dumps(e, separators=(",", ":"))})
        msgs.append({"role": "assistant", "content": json.dumps(r, separators=(",", ":"))})
    msgs.append({"role": "user", "content": "Incident: " + json.dumps(ev, separators=(",", ":"))})
    return msgs


def parse_output(text):
    """Extract the first JSON array/object from model text."""
    t = text.strip()
    t = re.sub(r"^```(?:json)?", "", t).strip()
    start = min([i for i in (t.find("["), t.find("{")) if i >= 0], default=-1)
    if start < 0: raise ValueError("output contains no JSON")
    depth, end, opener = 0, None, t[start]
    closer = "]" if opener == "[" else "}"
    instr = False; esc = False
    for i in range(start, len(t)):
        ch = t[i]
        if instr:
            if esc: esc = False
            elif ch == "\\": esc = True
            elif ch == '"': instr = False
            continue
        if ch == '"': instr = True
        elif ch == opener: depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0: end = i; break
    if end is None: raise ValueError("unterminated JSON (output truncated)")
    obj = json.loads(t[start:end + 1])
    if isinstance(obj, dict): obj = [obj]
    if not isinstance(obj, list): raise ValueError("JSON is not an array of rules")
    return obj


# ---------------------------------------------------------------------- templates
def template(inc, rung=0):
    """Template ladder. rung 0 is the classic per-class template (unverified baseline R2);
    higher rungs are progressively narrower/softer fall-backs used by the verified ladder."""
    sw, port = inc["loc"]
    cls = inc["cls"]
    eth, ip = (inc["identities"][0] if inc["identities"] else (None, None))
    ttl = 300
    if cls == "Linkfab":
        rules = [{"match": {"in_port": port, "eth_type": N.ETH_LLDP}, "action": "drop", "switches": [sw], "priority": 100, "ttl": ttl}]
        for s2, p2 in inc.get("extra_locs", []):
            rules.append({"match": {"in_port": p2, "eth_type": N.ETH_LLDP}, "action": "drop", "switches": [s2], "priority": 100, "ttl": ttl})
        ladder = [rules, rules[:1]]
    elif cls == "Hijack":
        ladder = [[{"match": {"in_port": port, "eth_src": eth}, "action": "drop", "switches": [sw], "priority": 100, "ttl": ttl}]]
    elif cls == "Injection":
        ladder = [[{"match": {"in_port": port}, "action": "drop", "switches": [sw], "priority": 100, "ttl": ttl}],
                  [{"match": {"in_port": port, "eth_type": N.ETH_ARP}, "action": "drop", "switches": [sw], "priority": 100, "ttl": ttl}]]
    else:  # DDoS / PortScan: classic "shun the source IP"
        ladder = [[{"match": {"eth_type": N.ETH_IP, "ip_src": ip}, "action": "drop", "switches": ["*"], "priority": 100, "ttl": ttl}],
                  [{"match": {"eth_type": N.ETH_IP, "ip_src": ip}, "action": "drop", "switches": [sw], "priority": 100, "ttl": ttl}],
                  [{"match": {"in_port": port, "eth_type": N.ETH_IP, "ip_src": ip}, "action": "drop", "switches": [sw], "priority": 100, "ttl": ttl}],
                  [{"match": {"in_port": port}, "action": "drop", "switches": [sw], "priority": 100, "ttl": ttl}]]
    ladder.append(conservative(inc))
    return ladder if rung is None else ladder[min(rung, len(ladder) - 1)]


def conservative(inc):
    sw, port = inc["loc"]
    return [{"match": {"in_port": port}, "action": "meter", "rate_kbps": 1000, "switches": [sw], "priority": 100, "ttl": 60}]


SYSTEM_SFT = ("You are the mitigation module of an SDN controller. For the incident, reply with only a JSON array "
              "of OpenFlow table-0 rules {match, action, rate_kbps (meter only), switches, priority, ttl}.")


def build_messages_sft(ev):
    return [{"role": "system", "content": SYSTEM_SFT},
            {"role": "user", "content": "Incident: " + json.dumps(ev, separators=(",", ":"))}]
