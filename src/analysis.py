"""Loading, per-run metric extraction and statistics for both papers."""
import os, json, math
import numpy as np, pandas as pd
from scipy import stats

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(ROOT, "results")
CENSOR = 60.0   # attack duration: an attack never brought to <=50% delivery gets TTM = 60 s


def load(grid):
    rows = []
    p = os.path.join(RES, grid + ".jsonl")
    seen = set()
    for l in open(p):
        d = json.loads(l)
        if "error" in d or d["id"] in seen: continue
        seen.add(d["id"])
        rows.append(d)
    return rows


def flat_A(rows):
    out = []
    for d in rows:
        o = d["out"]
        lat = [i["lat"] for i in d["incidents"] if i.get("lat")]
        inc = d["incidents"]
        base = dict(resp=d["resp"], topo=d["topo"], cls=d.get("cls"), seed=d["seed"], fp=d.get("fp", 0.0),
                    det=d.get("det", "full"),
                    collateral=o["collateral"], benign_fail=o["benign_fail"], attack_fail=o["attack_fail"],
                    prot_avail=o["prot_avail"], intercepted=o.get("intercepted", 0.0),
                    rules_installed=o["rules_installed"], rules_end=o["rules_end"],
                    incidents=len(inc), fp_incidents=d["rstats"].get("fp_incidents", 0),
                    llm_calls=d["rstats"].get("llm_calls", 0),
                    attempts=np.mean([i["attempts"] for i in inc]) if inc else np.nan,
                    fallback=np.mean([i["outcome"] == "fallback" for i in inc]) if inc else np.nan,
                    none=np.mean([i["outcome"] == "none" for i in inc]) if inc else np.nan,
                    first_try=np.mean([str(i["outcome"]).endswith("try0") or i["outcome"] in ("rung0", "template", "portdrop") for i in inc]) if inc else np.nan,
                    loop_s=np.mean([sum(v for k, v in l.items() if k != "queue") for l in lat]) if lat else np.nan,
                    synth_s=np.mean([l.get("synth", 0) for l in lat]) if lat else np.nan,
                    verify_s=np.mean([l.get("verify", 0) for l in lat]) if lat else np.nan,
                    twin_s=np.mean([l.get("twin", 0) for l in lat]) if lat else np.nan,
                    queue_s=np.mean([l.get("queue", 0) for l in lat]) if lat else np.nan,
                    install_s=np.mean([l.get("install", 0) for l in lat]) if lat else np.nan,
                    pruned=sum(i.get("pruned", 0) for i in inc))
        rej = {}
        for i in inc:
            for r in i.get("rejects") or []: rej[r] = rej.get(r, 0) + 1
        for k, v in rej.items(): base["rej_" + k] = v
        # rule-table footprint: entries per incident
        base["rules_per_inc"] = o["rules_installed"] / max(len(inc), 1)
        for aid, a in o["attacks"].items():
            r = dict(base, attack=aid.split(":")[0], residual=a["residual"],
                     ttm=a["ttm"] if a["ttm"] is not None else np.inf,
                     ttm_c=a["ttm"] if a["ttm"] is not None else CENSOR,
                     mitigated=a["ttm"] is not None)
            out.append(r)
    return pd.DataFrame(out)


def flat_B(rows):
    out = []
    for d in rows:
        o = d["out"]
        inc = d["incidents"]
        atk = d["atk"]
        adv = atk[0]
        gen = [a for a in atk[1:]]
        r = dict(resp=d["resp"], obj=d["scen"], topo=d["topo"], budget=d["budget"], seed=d["seed"],
                 adv_kind=adv["kind"],
                 collateral=o["collateral"], prot_avail=o["prot_avail"], prot_fail_rule=o["prot_fail_rule"],
                 host_down_rule=o["host_down_rule"], lost_bytes_rule=o["lost_bytes_rule"],
                 adv_pkts=o["adv_pkts"], adv_bytes=o["adv_bytes"],
                 # adversary-induced harm: only rules installed for incidents triggered by attack traffic
                 downtime_per_kpkt=1e3 * o.get("host_down_rule_adv", o["host_down_rule"]) / max(o["adv_pkts"], 1),
                 amplification=o.get("lost_bytes_rule_adv", o["lost_bytes_rule"]) / max(o["adv_bytes"], 1),
                 fp_harm_bytes=o.get("lost_bytes_rule_fp", np.nan), fp_down=o.get("host_down_rule_fp", np.nan),
                 attributed="lost_bytes_rule_adv" in o,
                 rules_installed=o["rules_installed"], rules_max=o["rules_max"],
                 rules_per_min=o["rules_installed"] / 2.0,
                 incidents=len(inc), llm_calls=d["rstats"].get("llm_calls", 0),
                 loop_p95=np.percentile([i["t_done"] - i["t_alert"] for i in inc if i.get("t_done")], 95) if any(i.get("t_done") for i in inc) else np.nan,
                 stale=d["rstats"].get("stale", 0),
                 spoof_tp=sum(1 for i in inc if i.get("spoof_flag") and i.get("spoof_truth")),
                 spoof_fp=sum(1 for i in inc if i.get("spoof_flag") and not i.get("spoof_truth")),
                 spoof_fn=sum(1 for i in inc if not i.get("spoof_flag") and i.get("spoof_truth")),
                 adv_residual=o["attacks"][list(o["attacks"])[0]]["residual"])
        if gen:
            g = o["attacks"][list(o["attacks"])[1]]
            r["gen_ttm"] = g["ttm"] if g["ttm"] is not None else np.inf
            r["gen_ttm_c"] = g["ttm"] if g["ttm"] is not None else CENSOR
            r["gen_residual"] = g["residual"]
        out.append(r)
    return pd.DataFrame(out)


def boot_ci(x, n=2000, fn=np.mean, seed=0):
    x = np.asarray([v for v in x if v is not None and not (isinstance(v, float) and math.isnan(v))], float)
    if len(x) == 0: return (np.nan, np.nan, np.nan)
    rng = np.random.default_rng(seed)
    bs = [fn(rng.choice(x, len(x))) for _ in range(n)]
    return fn(x), np.percentile(bs, 2.5), np.percentile(bs, 97.5)


def holm(p):
    p = np.asarray(p, float); m = len(p); order = np.argsort(p)
    adj = np.empty(m); run = 0.0
    for k, i in enumerate(order):
        run = max(run, (m - k) * p[i]); adj[i] = min(1.0, run)
    return adj


def paired(df, a, b, metric, keys=("topo", "cls", "seed", "attack")):
    """Paired Wilcoxon signed-rank test of responder a vs b on matched cells, with the
    matched-pairs rank-biserial correlation as effect size."""
    keys = [k for k in keys if k in df.columns]
    A = df[df.resp == a].set_index(keys)[metric]
    B = df[df.resp == b].set_index(keys)[metric]
    j = pd.concat([A, B], axis=1, keys=["a", "b"]).dropna()
    j = j[np.isfinite(j.a) & np.isfinite(j.b)]
    d = (j.a - j.b).values
    nz = d[d != 0]
    if len(nz) < 1: return dict(n=len(j), p=1.0, rbc=0.0, mean_a=j.a.mean(), mean_b=j.b.mean())
    w = stats.wilcoxon(nz)
    r = stats.rankdata(np.abs(nz))
    rbc = (r[nz > 0].sum() - r[nz < 0].sum()) / r.sum()
    return dict(n=len(j), p=float(w.pvalue), rbc=float(rbc), mean_a=j.a.mean(), mean_b=j.b.mean())


def fmt_ci(t, pct=False, d=3):
    m, lo, hi = t
    if pct: return f"{100 * m:.{max(d - 2, 1)}f} [{100 * lo:.{max(d - 2, 1)}f}, {100 * hi:.{max(d - 2, 1)}f}]"
    return f"{m:.{d}f} [{lo:.{d}f}, {hi:.{d}f}]"
