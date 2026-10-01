"""Flow-level OpenFlow network emulator with a Ryu-like reactive controller.

Models the parts of an SDN that matter for automated response:
  * physical topology (switches, ports, hosts, a legacy shared-access segment);
  * controller state: LLDP-discovered directed links (with liveness timeout) and a
    MAC host-tracking table learned from Packet-In (both poisonable);
  * a security table (OpenFlow table 0) holding responder rules with priority,
    TTL, drop / meter / redirect actions, evaluated hop-by-hop before forwarding;
  * link capacity (congestion), controller Packet-In capacity and per-switch flow
    table capacity.
Forwarding follows the controller's view (so link fabrication and host hijacking
really divert traffic), while delivery is decided on the physical network.
"""
import itertools, random
import networkx as nx

FIELDS = ("in_port", "eth_src", "eth_dst", "eth_type", "ip_src", "ip_dst", "ip_proto", "tp_src", "tp_dst", "arp_op")
ETH_IP, ETH_ARP, ETH_LLDP = 0x0800, 0x0806, 0x88CC
LLDP_PERIOD, LINK_TIMEOUT = 5.0, 15.0
HOST_BW, CORE_BW = 100.0, 1000.0          # Mbit/s
PKTIN_CAP = 500.0                         # Packet-In/s the controller can process
TABLE_CAP = 1000                          # flow entries per switch
REACTIVE_IDLE = 10.0                      # idle timeout of reactive entries (s)

SERVICES = {  # name: (ip_proto, tp_dst, duration s, share for clients, share for IoT devices)
    "dns": (17, 53, 0.1, 0.30, 0.20),
    "web": (6, 80, 0.5, 0.25, 0.00),
    "gw": (6, 443, 1.0, 0.20, 0.00),
    "mqtt": (6, 1883, 0.2, 0.10, 0.70),
    "ssh": (6, 22, 5.0, 0.05, 0.00),
    "ftp": (6, 21, 3.0, 0.05, 0.00),
    "coap": (17, 5683, 0.1, 0.00, 0.10),
}
PROTECTED = ("dns", "mqtt", "gw")
# LAN-SDN-NIDS last_layer values used to pick realistic Normal records per service
SERVICE_LAYER = {"dns": ["DNS"], "web": ["HTTP", "TCP"], "gw": ["TCP"], "mqtt": ["TCP"],
                 "ssh": ["SSH", "SSHv2"], "ftp": ["FTP", "FTP-DATA"], "coap": ["UDP"], "rtp": ["RTP", "UDP"],
                 "arp": ["ARP"], "icmp": ["ICMP"]}


def mac(i):
    return "00:00:00:00:%02x:%02x" % (i // 256, i % 256)


class Host:
    def __init__(self, name, idx, ip, sw, port, role, service=None):
        self.name, self.mac, self.ip, self.sw, self.port = name, mac(idx), ip, sw, port
        self.role, self.service = role, service   # role: client | iot | server


class Topology:
    """Physical topology. links: (u, pu, v, pv) undirected, bw in Mbit/s."""

    def __init__(self, name):
        self.name = name
        self.switches, self.hosts, self.links = [], [], []
        self.nport = {}
        self.shared_port = None       # (sw, port) of the legacy shared-access segment
        self.server_of = {}

    def add_switch(self, s):
        self.switches.append(s); self.nport[s] = 0

    def _port(self, s):
        self.nport[s] += 1; return self.nport[s]

    def link(self, u, v):
        self.links.append((u, self._port(u), v, self._port(v)))

    def host(self, name, sw, role, service=None, ip=None, shared=False):
        idx = len(self.hosts) + 1
        if shared:
            if self.shared_port is None or self.shared_port[0] != sw:
                self.shared_port = (sw, self._port(sw))
            port = self.shared_port[1]
        else:
            port = self._port(sw)
        ip = ip or "10.0.%d.%d" % (idx // 250, idx % 250 + 1)
        h = Host(name, idx, ip, sw, port, role, service)
        self.hosts.append(h)
        if service: self.server_of[service] = h
        return h

    def edge_ports(self, sw):
        return {h.port for h in self.hosts if h.sw == sw}


def build(name, seed=0):
    t = Topology(name)
    S = lambda n: [t.add_switch("s%d" % i) or "s%d" % i for i in range(1, n + 1)]
    c = 0

    def clients(sw, n, role="client", shared=0):
        nonlocal c
        for k in range(n):
            c += 1; t.host("h%d" % c, sw, role)
        for k in range(shared):
            c += 1; t.host("h%d" % c, sw, role, shared=True)

    if name == "linear":
        s = S(4); [t.link(s[i], s[i + 1]) for i in range(3)]
        srv = {"dns": "s1", "gw": "s1", "web": "s2", "ftp": "s3", "ssh": "s3", "mqtt": "s4"}
        for i, sw in enumerate(s): clients(sw, 3, shared=3 if sw == "s3" else 0)
    elif name == "tree":
        s = S(4); [t.link("s1", x) for x in s[1:]]
        srv = {"dns": "s1", "gw": "s1", "mqtt": "s2", "web": "s3", "ftp": "s4", "ssh": "s4"}
        for sw in s[1:]: clients(sw, 3, shared=3 if sw == "s4" else 0)
    elif name == "star":
        s = S(5); [t.link("s1", x) for x in s[1:]]
        srv = {"dns": "s1", "gw": "s1", "mqtt": "s1", "web": "s1", "ftp": "s1", "ssh": "s1"}
        for sw in s[1:]: clients(sw, 3, shared=3 if sw == "s5" else 0)
    elif name == "mesh":
        s = S(4); [t.link(a, b) for a, b in itertools.combinations(s, 2)]
        srv = {"dns": "s1", "gw": "s1", "web": "s2", "mqtt": "s3", "ftp": "s4", "ssh": "s4"}
        for sw in s: clients(sw, 3, shared=3 if sw == "s2" else 0)
    elif name == "subnets":
        s = S(4); [t.link("s1", x) for x in s[1:]]
        srv = {"dns": "s1", "gw": "s1", "web": "s1", "mqtt": "s2", "ftp": "s3", "ssh": "s4"}
        for sw in s[1:]: clients(sw, 4, shared=3 if sw == "s3" else 0)
    elif name == "iot":
        s = S(3); t.link("s1", "s2"); t.link("s1", "s3")
        srv = {"dns": "s1", "gw": "s1", "mqtt": "s1", "coap": "s1", "web": "s3"}
        clients("s2", 10, role="iot", shared=3)
        clients("s3", 4)
    else:
        raise ValueError(name)
    for svc, sw in srv.items():
        t.host(svc, sw, "server", service=svc, ip="10.0.9.%d" % (list(SERVICES).index(svc) + 1))
    if "coap" not in srv:
        pass
    return t


def match(rule_match, hdr, in_port, symbolic=False):
    """OpenFlow exact/wildcard match. hdr values of None are unknown (symbolic):
    a rule constraining that field *may* match; with symbolic=True we answer True."""
    for k, v in rule_match.items():
        hv = in_port if k == "in_port" else hdr.get(k)
        if hv is None:
            if symbolic: continue
            return False
        if hv != v:
            return False
    return True


class Rule:
    _ids = itertools.count(1)

    def __init__(self, match, action, switches, priority=100, ttl=60, rate_kbps=None,
                 t_install=0.0, owner="responder", incident=None, tag=""):
        self.id = next(Rule._ids)
        self.match, self.action, self.switches = dict(match), action, list(switches)
        self.priority, self.ttl, self.rate_kbps = priority, ttl, rate_kbps
        self.t_install, self.t_expire = t_install, t_install + ttl
        self.owner, self.incident, self.tag = owner, incident, tag

    def as_json(self):
        d = {"match": self.match, "action": self.action, "switches": self.switches,
             "priority": self.priority, "ttl": self.ttl}
        if self.action == "meter": d["rate_kbps"] = self.rate_kbps
        return d


class Network:
    """Physical network + controller view + security table."""

    def __init__(self, topo, rng):
        self.t, self.rng = topo, rng
        self.G = nx.Graph()
        self.port_peer = {}              # (sw, port) -> (sw', port') for inter-switch links
        for u, pu, v, pv in topo.links:
            self.G.add_edge(u, v, bw=CORE_BW)
            self.port_peer[(u, pu)] = (v, pv); self.port_peer[(v, pv)] = (u, pu)
        self.by_mac = {h.mac: h for h in topo.hosts}
        self.by_ip = {h.ip: h for h in topo.hosts}
        self.by_name = {h.name: h for h in topo.hosts}
        # controller state
        self.links = {}                  # directed (u, pu, v, pv) -> last LLDP time
        for u, pu, v, pv in topo.links:
            self.links[(u, pu, v, pv)] = 0.0; self.links[(v, pv, u, pu)] = 0.0
        self.fake_links = set()          # directed links that exist only in the controller's view
        self.host_table = {h.mac: (h.sw, h.port) for h in topo.hosts}
        self.binding = {h.ip: (h.mac, h.sw, h.port) for h in topo.hosts}   # stable (warm-up) bindings
        self.rules = []                  # active security-table rules
        self.rule_log = []               # all rules ever installed
        self.reactive = {s: {} for s in topo.switches}   # key -> expiry  (reactive entries)
        self._view_ver, self._path_cache = 0, {}
        self.link_lost_by = {}           # directed link -> rule id that suppressed its LLDP

    # ---------------- controller view ----------------
    def view_links(self, now):
        return [l for l, ts in self.links.items() if now - ts <= LINK_TIMEOUT or l in self.fake_links and now - ts <= LINK_TIMEOUT]

    def refresh_view(self, now):
        live = frozenset(self.view_links(now))
        if getattr(self, "_live", None) != live:
            self._live = live; self._view_ver += 1; self._path_cache = {}
            D = nx.DiGraph()
            D.add_nodes_from(self.t.switches)
            for (u, pu, v, pv) in sorted(live):   # deterministic edge order -> deterministic shortest-path ties
                D.add_edge(u, v, out_port=pu, in_port=pv, fake=(u, pu, v, pv) in self.fake_links)
            self.D = D

    def route(self, s_from, s_to):
        key = (s_from, s_to)
        if key not in self._path_cache:
            try:
                self._path_cache[key] = nx.shortest_path(self.D, s_from, s_to)
            except nx.NetworkXNoPath:
                self._path_cache[key] = None
        return self._path_cache[key]

    def rules_on(self, sw, now):
        return [r for r in self.rules if (r.switches == ["*"] or sw in r.switches) and r.t_install <= now < r.t_expire]

    def expire(self, now):
        keep = [r for r in self.rules if now < r.t_expire]
        gone = [r for r in self.rules if now >= r.t_expire]
        self.rules = keep
        return gone

    def install(self, rule):
        self.rules.append(rule); self.rule_log.append(rule)

    # ---------------- data plane ----------------
    def sec_table(self, sw, hdr, in_port, now, rules=None, symbolic=False):
        best = None
        for r in (rules if rules is not None else self.rules_on(sw, now)):
            if (r.switches == ["*"] or sw in r.switches) and match(r.match, hdr, in_port, symbolic):
                if best is None or r.priority > best.priority:
                    best = r
        return best

    def deliver(self, src_loc, hdr, dst_mac, now, rules=None, symbolic=False):
        """Walk a packet from its physical ingress (sw, port) toward dst_mac.
        Returns (status, rule, hops). status in ok | drop | meter | redirect | divert | noroute
        | intercept(ok but via a fabricated link)."""
        sw, port = src_loc
        loc = self.host_table.get(dst_mac)
        if loc is None:
            return "noroute", None, []
        path = self.route(sw, loc[0])
        if path is None:
            return "noroute", None, []
        intercepted, metered = False, None
        for i, s in enumerate(path):
            r = self.sec_table(s, hdr, port, now, rules, symbolic)
            if r is not None:
                if r.action == "drop": return "drop", r, path[:i + 1]
                if r.action == "redirect": return "redirect", r, path[:i + 1]
                if r.action == "meter" and metered is None: metered = r
            if i + 1 < len(path):
                e = self.D.edges[s, path[i + 1]]
                if e["fake"]: intercepted = True
                port = e["in_port"]
        phys = self.by_mac.get(dst_mac)
        if phys is not None and (phys.sw, phys.port) != loc:
            return "divert", None, path
        if metered is not None:
            return "meter", metered, path
        return ("intercept" if intercepted else "ok"), None, path

    def lldp_tick(self, now, lldp_rules=None):
        """Every LLDP period each switch floods LLDP; a directed link u->v is refreshed if the
        LLDP frame arriving at (v, pv) is not dropped by v's security table."""
        for (u, pu, v, pv) in list(self.links):
            if (u, pu, v, pv) in self.fake_links:
                continue
            hdr = {"eth_type": ETH_LLDP, "eth_src": "lldp:%s:%d" % (u, pu), "eth_dst": "01:80:c2:00:00:0e"}
            r = self.sec_table(v, hdr, pv, now)
            if r is None or r.action == "meter":
                self.links[(u, pu, v, pv)] = now
                self.link_lost_by.pop((u, pu, v, pv), None)
            else:
                self.link_lost_by[(u, pu, v, pv)] = r.id
