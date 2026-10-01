"""Containernet + Open vSwitch + Ryu validation of the emulator's data-plane / reachability predictions.
Run as root inside WSL:  python3 validate.py [topo ...]"""
import json, os, sys, time, subprocess, threading, requests
from mininet.net import Containernet
from mininet.node import RemoteController, OVSSwitch
from mininet.nodelib import LinuxBridge
from mininet.log import setLogLevel

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = json.load(open(os.path.join(HERE, "rulesets.json")))
OUT = os.path.join(HERE, os.environ.get("OUTFILE", "results_real.jsonl"))
ONLY = set(os.environ.get("ONLY_IDS", "").split(",")) - {""}
FLUSH_ARP = os.environ.get("FLUSH_ARP") == "1"
REST = "http://127.0.0.1:8080"
COOKIE = 0x5E
SVC = {"dns": ("udp", 53), "web": ("tcp", 80), "gw": ("tcp", 443), "mqtt": ("tcp", 1883), "ssh": ("tcp", 22),
       "ftp": ("tcp", 21), "coap": ("udp", 5683)}


def dpid(sw):
    return int(sw[1:])


def of_match(m):
    """Emulator match -> ofctl_rest (OpenFlow 1.3) match. Returns None if OVS would reject it."""
    o = {}
    proto = m.get("ip_proto")
    for k, v in m.items():
        if k == "ip_src": o["ipv4_src"] = v
        elif k == "ip_dst": o["ipv4_dst"] = v
        elif k in ("tp_src", "tp_dst"):
            if proto not in (6, 17): return None
            o[("tcp_" if proto == 6 else "udp_") + k[3:]] = v
        elif k in ("in_port", "eth_src", "eth_dst", "eth_type", "ip_proto", "arp_op"):
            o[k] = v
    if any(k.startswith("ipv4") or k == "ip_proto" for k in o) and o.get("eth_type") != 0x0800: return None
    if "arp_op" in o and o.get("eth_type") != 0x0806: return None
    for k, v in o.items():
        if isinstance(v, str) and k in ("ipv4_src", "ipv4_dst") and (v.startswith("[") or "," in v): return None
    return o


def install(rules, switches):
    """Install a rule set in table 0 of every target switch; returns (#installed, #rejected, latency list)."""
    n_ok = n_rej = 0
    lat = []
    meter_id = 1
    for r in rules:
        m = of_match(r["match"])
        if m is None:
            n_rej += 1; continue
        targets = switches if r["switches"] == ["*"] else [s for s in r["switches"] if s in switches]
        for sw in targets:
            acts = []
            if r["action"] == "meter":
                requests.post(REST + "/stats/meterentry/add", json={"dpid": dpid(sw), "flags": "KBPS", "meter_id": meter_id,
                                                                  "bands": [{"type": "DROP", "rate": int(r.get("rate_kbps") or 1000)}]})
                acts = [{"type": "METER", "meter_id": meter_id}, {"type": "GOTO_TABLE", "table_id": 1}]
            t0 = time.perf_counter()
            resp = requests.post(REST + "/stats/flowentry/add", json={"dpid": dpid(sw), "table_id": 0, "priority": 100,
                                                                     "cookie": COOKIE, "match": m, "actions": acts})
            if resp.status_code != 200:
                n_rej += 1; continue
            # installation latency: REST call until the entry is visible in the switch
            for _ in range(200):
                out = subprocess.run(["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", sw, "table=0,cookie=0x5e/-1"],
                                     capture_output=True, text=True).stdout
                if out.count("cookie=0x5e") >= 1: break
                time.sleep(0.002)
            lat.append((time.perf_counter() - t0) * 1e3)
            n_ok += 1
        meter_id += 1
    return n_ok, n_rej, lat


def clear(switches):
    for sw in switches:
        requests.post(REST + "/stats/flowentry/delete", json={"dpid": dpid(sw), "table_id": 0, "cookie": COOKIE,
                                                             "cookie_mask": 0xFFFFFFFFFFFFFFFF, "priority": 100})
        requests.post(REST + "/stats/meterentry/delete", json={"dpid": dpid(sw), "meter_id": 0xFFFFFFFF})
    time.sleep(0.3)


def probe_all(net, preds):
    by_host = {}
    for i, p in enumerate(preds):
        by_host.setdefault(p["host"], []).append((i, [p["ip"], p["proto"], p["port"]]))
    res = [None] * len(preds)

    def run(h, items):
        out = net.get(h).cmd("python3 /opt/probe.py '%s'" % json.dumps([t for _, t in items]))
        try:
            vals = json.loads(out.strip().splitlines()[-1])
        except Exception:
            vals = [False] * len(items)
        for (i, _), v in zip(items, vals): res[i] = bool(v)
    th = [threading.Thread(target=run, args=(h, it)) for h, it in by_host.items()]
    [t.start() for t in th]; [t.join() for t in th]
    return res


def cleanup():
    """Remove leftovers of an interrupted run (containers mn.*, OVS bridges, stray veths)."""
    ids = subprocess.run(["docker", "ps", "-aq", "--filter", "name=mn."], capture_output=True, text=True).stdout.split()
    if ids: subprocess.run(["docker", "rm", "-f"] + ids, capture_output=True)
    for br in subprocess.run(["ovs-vsctl", "list-br"], capture_output=True, text=True).stdout.split():
        subprocess.run(["ovs-vsctl", "del-br", br], capture_output=True)
    links = subprocess.run(["ip", "-o", "link"], capture_output=True, text=True).stdout.splitlines()
    for l in links:
        nm = l.split(":")[1].strip().split("@")[0]
        if nm.startswith(("s", "lb")) and "-eth" in nm or nm == "lb1":
            subprocess.run(["ip", "link", "del", nm], capture_output=True)
    subprocess.run(["pkill", "-f", "ryu-manager"], capture_output=True)
    time.sleep(1)


def run_topology(name):
    T = DATA["topologies"][name]
    sets = [s for s in DATA["sets"] if s["topo"] == name and (not ONLY or s["id"] in ONLY)][:int(os.environ.get("MAXSETS", "999"))]
    if not sets: return
    cleanup()
    os.makedirs("/opt/vmval", exist_ok=True)
    subprocess.run(["cp", os.path.join(HERE, "vm_switch.py"), "/opt/vmval/vm_switch.py"])   # ryu splits app args on ','
    ryu = subprocess.Popen(["ryu-manager", "/opt/vmval/vm_switch.py", "ryu.app.ofctl_rest"],
                           stdout=open(f"/tmp/ryu_{name}.log", "w"), stderr=subprocess.STDOUT)
    time.sleep(4)
    net = Containernet(controller=RemoteController, switch=OVSSwitch, build=False, autoSetMacs=False)
    net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6653)
    sw = {s: net.addSwitch(s, protocols="OpenFlow13", dpid="%016x" % dpid(s)) for s in T["switches"]}
    for u, pu, v, pv in T["links"]:
        net.addLink(sw[u], sw[v], port1=pu, port2=pv)
    shared = tuple(T["shared"]) if T["shared"] else None
    lb = None
    if shared:
        lb = net.addSwitch("lb1", cls=LinuxBridge)
        net.addLink(lb, sw[shared[0]], port2=shared[1])
    for h in T["hosts"]:
        d = net.addDocker(h["name"], ip=h["ip"] + "/16", mac=h["mac"], dimage="vmval:latest")
        if shared and (h["sw"], h["port"]) == shared:
            net.addLink(d, lb)
        else:
            net.addLink(d, sw[h["sw"]], port2=h["port"])
    net.build(); net.start()
    for h in T["hosts"]:
        if h["role"] == "server":
            p, port = SVC[h["service"]]
            net.get(h["name"]).cmd(f"nohup python3 /opt/svc.py {p}:{port} > /dev/null 2>&1 &")
    time.sleep(2)
    base = sets[0]["pred"]
    for attempt in range(6):          # warm-up: learning + ARP
        ok = probe_all(net, base)
        if sum(ok) >= len(ok) - 0: break
        time.sleep(1)
    base_ok = sum(ok) / len(ok)
    print(name, "baseline reachability", round(base_ok, 4), flush=True)
    with open(OUT, "a") as f:
        for s in sets:
            clear(T["switches"])
            n_ok, n_rej, lat = install(s["rules"], T["switches"])
            if FLUSH_ARP:     # cold ARP caches: every pair must resolve its peer through the rules under test
                for h in T["hosts"]:
                    net.get(h["name"]).cmd("ip neigh flush all")
            time.sleep(1.0)
            real = probe_all(net, s["pred"])
            clear(T["switches"])
            f.write(json.dumps(dict(id=s["id"], topo=name, resp=s["resp"], grid=s["grid"], scen=s["scen"],
                                    installed=n_ok, rejected=n_rej, install_ms=lat, baseline=base_ok,
                                    pred=[p["pred"] for p in s["pred"]], real=real,
                                    pairs=[[p["host"], p["svc"]] for p in s["pred"]])) + "\n")
            f.flush()
    net.stop()
    ryu.terminate(); ryu.wait()
    try:
        subprocess.run(["mn", "-c"], capture_output=True)
    except FileNotFoundError:
        pass


if __name__ == "__main__":
    setLogLevel("warning")
    topos = sys.argv[1:] or list(DATA["topologies"])
    for t in topos:
        run_topology(t)
    print("VALDONE")
