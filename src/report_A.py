"""Paper A: tables, figures and LaTeX number macros from the result logs."""
import os, json, math, collections
import numpy as np, pandas as pd
import analysis as A
import figures as F
import matplotlib.pyplot as plt

OUT = os.path.join(A.ROOT, "paper_outputs"); os.makedirs(OUT, exist_ok=True)
ORDER = ["none", "portdrop", "template", "vtemplate", "llm", "verimit"]
LBL = F.LBL
MAC = {}


def mac(name, val):
    MAC[name] = val


def pct(x, d=1): return f"{100 * x:.{d}f}"


def load_main():
    rows = A.load("A_main")
    return A.flat_A(rows), rows


def med_iqr(x):
    x = np.asarray(x, float)
    return np.median(x), np.percentile(x, 25), np.percentile(x, 75)


def table_main(df):
    L = [r"\begin{table*}[t]", r"\centering",
         r"\caption{Scenario M0 (single attack; 5 classes $\times$ 6 topologies $\times$ 5 seeds; one row per attack). Means with 95\% bootstrap CIs; TTM is the median with interquartile range, censored at 60\,s for attacks never mitigated. Collateral is the share of benign flows started during the attack that failed because of a responder rule.}",
         r"\label{tab:main}", r"\footnotesize", r"\setlength{\tabcolsep}{4pt}",
         r"\begin{tabular}{lcccccccc}", r"\toprule",
         r"Responder & Mitigated (\%) & TTM (s) & Residual attack (\%) & Collateral (\%) & Benign failures (\%) & Protected avail.\ (\%) & Rules/incident & Loop (s) \\",
         r"\midrule"]
    for r in ORDER:
        d = df[df.resp == r]
        if d.empty: continue
        m, q1, q3 = med_iqr(d.ttm_c)
        res = A.boot_ci(d.residual); col = A.boot_ci(d.collateral); bf = A.boot_ci(d.benign_fail)
        pa = A.boot_ci(d.prot_avail)
        ttm = "--" if r == "none" else f"{m:.1f} [{q1:.1f}, {q3:.1f}]"
        loop = "--" if r == "none" else f"{np.nanmean(d.loop_s):.2f}"
        rpi = "--" if r == "none" else f"{d.rules_per_inc.mean():.2f}"
        L.append(f"{LBL[r]} & {pct(d.mitigated.mean())} & {ttm} & {pct(res[0])} [{pct(res[1])}, {pct(res[2])}] & "
                 f"{pct(col[0], 2)} [{pct(col[1], 2)}, {pct(col[2], 2)}] & {pct(bf[0])} & {pct(pa[0])} & {rpi} & {loop} \\\\")
        key = {"none": "None", "portdrop": "Pd", "template": "Tp", "vtemplate": "Vt", "llm": "Llm", "verimit": "Vm"}[r]
        mac(f"coll{key}", pct(col[0], 2)); mac(f"collLo{key}", pct(col[1], 2)); mac(f"collHi{key}", pct(col[2], 2))
        mac(f"res{key}", pct(res[0])); mac(f"ttm{key}", f"{m:.1f}"); mac(f"mit{key}", pct(d.mitigated.mean()))
        mac(f"prot{key}", pct(pa[0])); mac(f"bfail{key}", pct(bf[0]))
    L += [r"\bottomrule", r"\end{tabular}", r"\end{table*}"]
    open(os.path.join(OUT, "tab_main.tex"), "w").write("\n".join(L) + "\n")


def table_tests(df, ref="verimit", others=("portdrop", "template", "vtemplate", "llm"),
                metrics=(("collateral", "Collateral"), ("ttm_c", "TTM"), ("residual", "Residual")), name="tab_tests"):
    rows, ps = [], []
    for o in others:
        for m, lab in metrics:
            t = A.paired(df, ref, o, m)
            rows.append((o, lab, t)); ps.append(t["p"])
    adj = A.holm(ps)
    L = [r"\begin{table}[t]", r"\centering",
         r"\caption{Paired comparisons of VeriMitigate with each baseline on matched M0 cells (Wilcoxon signed-rank, Holm-adjusted $p$; $r$ = matched-pairs rank-biserial correlation, negative = VeriMitigate lower).}",
         r"\label{tab:tests}", r"\footnotesize", r"\begin{tabular}{llrrcr}", r"\toprule",
         r"Baseline & Metric & VeriMit. & Baseline & $p_\mathrm{Holm}$ & $r$ \\", r"\midrule"]
    for (o, lab, t), pa in zip(rows, adj):
        fmt = (lambda v: f"{100 * v:.2f}\\%") if lab in ("Collateral", "Residual") else (lambda v: f"{v:.2f}")
        ptxt = "$<$0.001" if pa < 1e-3 else f"{pa:.3f}"
        L.append(f"{LBL[o]} & {lab} & {fmt(t['mean_a'])} & {fmt(t['mean_b'])} & {ptxt} & {t['rbc']:+.2f} \\\\")
        mac(f"p{o}{lab}", ptxt.replace("$<$", "<")); mac(f"r{o}{lab}", f"{t['rbc']:+.2f}")
    L += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    open(os.path.join(OUT, name + ".tex"), "w").write("\n".join(L) + "\n")


def table_class(df):
    cls = ["DDoS", "PortScan", "Injection", "Hijack", "Linkfab"]
    L = [r"\begin{table}[t]", r"\centering",
         r"\caption{Collateral (\%) and median TTM (s) per attack class in M0.}", r"\label{tab:class}",
         r"\footnotesize", r"\setlength{\tabcolsep}{3pt}", r"\begin{tabular}{l" + "cc" * len(cls) + "}", r"\toprule",
         "& " + " & ".join(rf"\multicolumn{{2}}{{c}}{{{c}}}" for c in cls) + r" \\",
         " ".join(rf"\cmidrule(lr){{{2 + 2 * i}-{3 + 2 * i}}}" for i in range(len(cls))),
         "Responder & " + " & ".join(["Coll.", "TTM"] * len(cls)) + r" \\", r"\midrule"]
    for r in ORDER[1:]:
        d = df[df.resp == r]
        if d.empty: continue
        cells = []
        for c in cls:
            x = d[d.attack == c]
            cells += [f"{100 * x.collateral.mean():.2f}", f"{np.median(x.ttm_c):.1f}"]
        L.append(f"{LBL[r]} & " + " & ".join(cells) + r" \\")
    L += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    open(os.path.join(OUT, "tab_class.tex"), "w").write("\n".join(L) + "\n")


def table_topo(df):
    topos = ["linear", "tree", "star", "mesh", "subnets", "iot"]
    L = [r"\begin{table}[h]", r"\centering",
         r"\caption{Collateral (\%) / median TTM (s) per topology in M0 (subnets and IoT were not used to train the synthesizer).}",
         r"\label{tab:topo_res}", r"\footnotesize", r"\setlength{\tabcolsep}{3pt}", r"\begin{tabular}{l" + "c" * len(topos) + "}", r"\toprule",
         "Responder & " + " & ".join(t.capitalize() if t != "iot" else "IoT" for t in topos) + r" \\", r"\midrule"]
    for r in ORDER[1:]:
        d = df[df.resp == r]
        if d.empty: continue
        L.append(f"{LBL[r]} & " + " & ".join(f"{100 * d[d.topo == t].collateral.mean():.2f} / {np.median(d[d.topo == t].ttm_c):.1f}" for t in topos) + r" \\")
    L += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    open(os.path.join(OUT, "tab_topo_res.tex"), "w").write("\n".join(L) + "\n")
    for r, k in [("llm", "Llm"), ("verimit", "Vm"), ("vtemplate", "Vt")]:
        x = df[(df.resp == r) & (df.topo == "subnets")]
        mac(f"subnetsColl{k}", f"{100 * x.collateral.mean():.2f}")


def fig_tradeoff(df):
    fig, axes = plt.subplots(1, 3, figsize=(7.1, 2.3))
    order = [r for r in ORDER[1:] if r in set(df.resp)]
    g = df.groupby("resp")
    for ax, (metric, lab, sc, fmt) in zip(axes, [("ttm_c", "Median TTM (s)", 1, "{:.1f}"),
                                                ("residual", "Residual attack (%)", 100, "{:.1f}"),
                                                ("collateral", "Collateral (%)", 100, "{:.2f}")]):
        if metric == "ttm_c":
            vals = np.array([np.median(g.get_group(r)[metric]) for r in order]); errs = None
        else:
            vals, errs = F.ci_arrays(g, order, metric, sc)
        ax.set_ylim(0, (vals + (errs[1] if errs is not None else 0)).max() * 1.25)
        F.bars(ax, [LBL[r] for r in order], vals, errs, [F.C[r] for r in order], fmt=fmt, ylabel=lab)
    fig.tight_layout()
    F.save(fig, os.path.join(OUT, "fig_tradeoff.pdf"))


def m1_m4():
    out = {}
    try:
        d1 = A.flat_A(A.load("A_m1")); out["m1"] = d1
    except FileNotFoundError: pass
    try:
        d4 = A.flat_A(A.load("A_m4")); out["m4"] = d4
    except FileNotFoundError: pass
    if "m1" in out:
        d1 = out["m1"]
        L = [r"\begin{table}[t]", r"\centering",
             r"\caption{Scenario M1 (two concurrent attacks; 3 pairs $\times$ 6 topologies $\times$ 5 seeds). Means over attacks; TTM median.}",
             r"\label{tab:m1}", r"\footnotesize", r"\begin{tabular}{lccccc}", r"\toprule",
             r"Responder & Mitig.\ (\%) & TTM (s) & Residual (\%) & Collateral (\%) & Prot.\ avail.\ (\%) \\", r"\midrule"]
        for r in ORDER:
            d = d1[d1.resp == r]
            if d.empty: continue
            L.append(f"{LBL[r]} & {pct(d.mitigated.mean())} & {np.median(d.ttm_c):.1f} & {pct(d.residual.mean())} & "
                     f"{pct(d.collateral.mean(), 2)} & {pct(d.prot_avail.mean())} \\\\")
            if r == "portdrop": mac("mOneCollPd", pct(d.collateral.mean(), 2))
            if r == "verimit": mac("mOneCollVm", pct(d.collateral.mean(), 2))
            if r == "vtemplate": mac("mOneCollVt", pct(d.collateral.mean(), 2))
            if r == "llm": mac("mOneCollLlm", pct(d.collateral.mean(), 2))
            if r == "template": mac("mOneCollTp", pct(d.collateral.mean(), 2))
        L += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
        open(os.path.join(OUT, "tab_m1.tex"), "w").write("\n".join(L) + "\n")
    if "m4" in out:
        d4 = out["m4"]
        fig, ax = plt.subplots(figsize=(3.4, 2.3))
        for r in ["portdrop", "template", "vtemplate", "llm", "verimit", "vtemplate_D", "verimit_D"]:
            d = d4[d4.resp == r]
            if d.empty: continue
            s = d.groupby("fp").collateral.mean() * 100
            ax.plot(s.index * 100, s.values, "-o", color=F.C[r], lw=2, ms=4, label=LBL[r])
        ax.set_xlabel("Injected false-positive rate (% of benign records)"); ax.set_ylabel("Collateral (%)")
        ax.set_xticks([2, 5, 10]); ax.set_xlim(1, 11)
        ax.legend(fontsize=6.5, loc="upper left")
        F.save(fig, os.path.join(OUT, "fig_m4.pdf"))
        L = [r"\begin{table}[t]", r"\centering",
             r"\caption{Scenario M4 (injected detector false positives). Collateral (\%) / protected-service availability (\%) / incidents per run.}",
             r"\label{tab:m4}", r"\footnotesize", r"\begin{tabular}{lccc}", r"\toprule",
             r"Responder & FP 2\% & FP 5\% & FP 10\% \\", r"\midrule"]
        for r in ["portdrop", "template", "vtemplate", "llm", "verimit", "vtemplate_D", "verimit_D"]:
            d = d4[d4.resp == r]
            if d.empty: continue
            cells = []
            for fp in [0.02, 0.05, 0.10]:
                x = d[d.fp == fp]
                cells.append(f"{pct(x.collateral.mean(), 2)} / {pct(x.prot_avail.mean())} / {x.incidents.mean():.1f}")
            L.append(f"{LBL[r]} & " + " & ".join(cells) + r" \\")
            x = d[d.fp == 0.10]
            mac({"portdrop": "mFourPd", "template": "mFourTp", "vtemplate": "mFourVt", "llm": "mFourLlm", "verimit": "mFourVm",
                 "vtemplate_D": "mFourVtD", "verimit_D": "mFourVmD"}[r], pct(x.collateral.mean(), 2))
        L += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
        open(os.path.join(OUT, "tab_m4.tex"), "w").write("\n".join(L) + "\n")
    return out


ABL = [("verimit", "VeriMitigate (full)"), ("vm_no_semantics", "$-$ class semantics"), ("vm_no_ttl", "$-$ TTL check"),
       ("vm_no_scope", "$-$ scope check"), ("vm_no_conflict", "$-$ conflict check"), ("vm_no_reach", "$-$ reachability"),
       ("vm_no_blast", "$-$ blast radius"), ("vm_no_twin", "$-$ twin replay (A3)"), ("vm_no_cex", "$-$ counterexamples"),
       ("vm_no_prune", "$-$ pruning"), ("llm", "$-$ verifier and twin (A1)"), ("vm_dpo", "+ DPO with verifier reward (A5)"),
       ("vm_base_fewshot", "Base model, 5-shot, verified (A4)"), ("llm_base_fewshot", "Base model, 5-shot, unverified (A4)"),
       ("vm_provisional", "+ provisional meter")]


def table_ablation(main):
    try:
        ab = A.flat_A(A.load("A_abl"))
    except FileNotFoundError:
        return
    ref = main[main.resp.isin(["verimit", "llm"])]
    d = pd.concat([ab, ref])
    L = [r"\begin{table*}[t]", r"\centering",
         r"\caption{Ablations on M0 (5 classes $\times$ 6 topologies $\times$ 5 seeds). First-try: share of incidents whose first synthesized candidate was installed; fallback: share resolved by the conservative meter; calls: LLM calls per incident.}",
         r"\label{tab:abl}", r"\footnotesize", r"\begin{tabular}{lcccccccc}", r"\toprule",
         r"Variant & Mitig.\ (\%) & TTM (s) & Residual (\%) & Collateral (\%) & Prot.\ avail.\ (\%) & First-try (\%) & Fallback (\%) & Calls/inc. \\",
         r"\midrule"]
    for r, lab in ABL:
        x = d[d.resp == r]
        if x.empty: continue
        calls = (x.llm_calls / x.incidents.clip(lower=1)).mean()
        L.append(f"{lab} & {pct(x.mitigated.mean())} & {np.median(x.ttm_c):.1f} & {pct(x.residual.mean())} & "
                 f"{pct(x.collateral.mean(), 2)} & {pct(x.prot_avail.mean())} & {pct(np.nanmean(x.first_try))} & "
                 f"{pct(np.nanmean(x.fallback))} & {calls:.2f} \\\\")
        MAC["abl" + "".join(ch for ch in r.title() if ch.isalpha())] = pct(x.collateral.mean(), 2)
        MAC["ablTtm" + "".join(ch for ch in r.title() if ch.isalpha())] = f"{np.median(x.ttm_c):.1f}"
        MAC["ablFt" + "".join(ch for ch in r.title() if ch.isalpha())] = pct(np.nanmean(x.first_try))
    L += [r"\bottomrule", r"\end{tabular}", r"\end{table*}"]
    open(os.path.join(OUT, "tab_abl.tex"), "w").write("\n".join(L) + "\n")
    # paired tests of each variant against the full system (collateral and TTM), Holm-corrected
    tests, ps = [], []
    for r, lab in ABL[1:]:
        if d[d.resp == r].empty: continue
        for m in ("collateral", "ttm_c"):
            t = A.paired(d, r, "verimit", m); tests.append((r, lab, m, t)); ps.append(t["p"])
    adj = A.holm(ps)
    T = [r"\begin{table}[t]", r"\centering",
         r"\caption{Paired Wilcoxon tests of each ablation against full VeriMitigate on matched M0 cells (Holm-adjusted $p$; $r$: rank-biserial correlation, positive = ablation higher).}",
         r"\label{tab:ablp}", r"\footnotesize", r"\begin{tabular}{lcccc}", r"\toprule",
         r"Variant & Collateral $p$ & $r$ & TTM $p$ & $r$ \\", r"\midrule"]
    by = {}
    for (r, lab, m, t), pa in zip(tests, adj): by.setdefault((r, lab), {})[m] = (pa, t["rbc"])
    fp = lambda p: "$<$0.001" if p < 1e-3 else f"{p:.3f}"
    for (r, lab), v in by.items():
        c, tt = v.get("collateral", (1, 0)), v.get("ttm_c", (1, 0))
        T.append(f"{lab} & {fp(c[0])} & {c[1]:+.2f} & {fp(tt[0])} & {tt[1]:+.2f} " + r"\\")
        key = "".join(ch for ch in r.title() if ch.isalpha())
        MAC["ablP" + key] = fp(c[0]).replace("$<$", "<"); MAC["ablPt" + key] = fp(tt[0]).replace("$<$", "<")
    T += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    open(os.path.join(OUT, "tab_ablp.tex"), "w").write("\n".join(T) + "\n")


def table_latency(rows):
    lat = {}
    for d in rows:
        if d["resp"] not in ("vtemplate", "llm", "verimit"): continue
        for i in d["incidents"]:
            if i.get("lat"): lat.setdefault(d["resp"], []).append(i["lat"])
    L = [r"\begin{table}[t]", r"\centering",
         r"\caption{Loop latency breakdown per incident in M0 (mean / 95th percentile, seconds). Synthesis is the measured single-request latency on a GTX~1060; the verifier column is its measured wall-clock time (the loop charges a fixed 20\,ms per verification); the twin is charged 1\,s per replay.}",
         r"\label{tab:lat}", r"\footnotesize", r"\setlength{\tabcolsep}{3pt}", r"\begin{tabular}{lcccccc}", r"\toprule",
         r"Responder & Queue & Synthesis & Verifier & Twin & Install & Total \\", r"\midrule"]
    for r in ("vtemplate", "llm", "verimit"):
        if r not in lat: continue
        X = pd.DataFrame(lat[r]).fillna(0.0)
        for c in ["queue", "synth", "verify", "twin", "install", "verify_meas", "detect"]:
            if c not in X: X[c] = 0.0
        X["total"] = X[["queue", "synth", "verify", "twin", "install", "detect"]].sum(1)
        X["verify"] = X["verify_meas"]          # report the measured verifier wall-clock time
        cells = [f"{X[c].mean():.2f} / {X[c].quantile(.95):.2f}" if c != "verify" else f"{1e3 * X[c].mean():.1f} / {1e3 * X[c].quantile(.95):.1f}\\,ms"
                 for c in ["queue", "synth", "verify", "twin", "install", "total"]]
        L.append(f"{LBL[r]} & " + " & ".join(cells) + r" \\")
        if r == "verimit":
            mac("latSynthVm", f"{X.synth.mean():.1f}"); mac("latVerifyVm", f"{1e3 * X.verify.mean():.1f}")
            mac("latTotalVm", f"{X.total.mean():.1f}"); mac("latVerifyVmP", f"{1e3 * X.verify.quantile(.95):.1f}")
        if r == "vtemplate":
            mac("latVerifyVt", f"{1e3 * X.verify.mean():.1f}"); mac("latTotalVt", f"{X.total.mean():.1f}")
    L += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    open(os.path.join(OUT, "tab_lat.tex"), "w").write("\n".join(L) + "\n")


def rejections(rows):
    rej, n_inc, n_att = {}, 0, 0
    for d in rows:
        if d["resp"] != "verimit": continue
        for i in d["incidents"]:
            n_inc += 1; n_att += i.get("attempts") or 0
            for r in i.get("rejects") or []: rej[r] = rej.get(r, 0) + 1
    mac("vmIncidents", str(n_inc)); mac("vmAttempts", str(n_att))
    mac("vmRejections", str(sum(rej.values())))
    for k, v in rej.items(): mac("rej" + k.title(), str(v))
    return rej, n_inc, n_att


def seen_unseen(df):
    d = df[df.resp == "verimit"]
    if d.empty: return
    for grp, topos in [("Seen", ["linear", "tree", "star", "mesh"]), ("Unseen", ["subnets", "iot"])]:
        x = d[d.topo.isin(topos)]
        mac(f"coll{grp}", pct(x.collateral.mean(), 2)); mac(f"res{grp}", pct(x.residual.mean()))
        mac(f"ft{grp}", pct(np.nanmean(x.first_try))); mac(f"ttm{grp}", f"{np.median(x.ttm_c):.1f}")
        mac(f"mit{grp}", pct(x.mitigated.mean()))


def det_ablation():
    try:
        dd = A.flat_A(A.load("A_det"))
    except FileNotFoundError:
        return
    for r, k in [("vtemplate", "Vt"), ("verimit", "Vm")]:
        x = dd[dd.resp == r]
        if x.empty: continue
        mac(f"detDp{k}Coll", pct(x.collateral.mean(), 2)); mac(f"detDp{k}Fp", f"{x.fp_incidents.mean():.2f}")
        mac(f"detDp{k}Res", pct(x.residual.mean()))
        y = A.flat_A(A.load("A_main"))
        y = y[(y.resp == r) & (y.seed < 3)]
        mac(f"detFull{k}Coll", pct(y.collateral.mean(), 2)); mac(f"detFull{k}Fp", f"{y.fp_incidents.mean():.2f}")


def speed(main):
    try:
        sp = A.flat_A(A.load("A_speed"))
    except FileNotFoundError:
        return
    base = main[(main.resp == "verimit") & (main.seed < 3)].copy(); base["resp"] = "vm_speed1"
    vt = main[(main.resp == "vtemplate") & (main.seed < 3)]
    d = pd.concat([base, sp])
    fac = {"vm_speed1": 1, "vm_speed2": 2, "vm_speed5": 5, "vm_speed10": 10, "vm_speed20": 20}
    d["speed"] = d.resp.map(fac)
    g = d.groupby("speed")
    x = sorted(g.groups)
    ttm = [np.median(g.get_group(k).ttm_c) for k in x]; res = [100 * g.get_group(k).residual.mean() for k in x]
    col = [100 * g.get_group(k).collateral.mean() for k in x]
    fig, axes = plt.subplots(1, 2, figsize=(6.6, 2.3))
    for ax, y, ref, lab in [(axes[0], ttm, np.median(vt.ttm_c), "Median TTM (s)"),
                            (axes[1], res, 100 * vt.residual.mean(), "Residual attack (%)")]:
        ax.plot(x, y, "-o", color=F.C["verimit"], lw=2, ms=4)
        ax.axhline(ref, color=F.C["vtemplate"], lw=1.6, ls="--")
        ax.text(x[1], ref + max(max(y), ref) * 0.03, "V-Template", color=F.INK, fontsize=6.5, va="bottom", ha="center")
        ax.minorticks_off()
        ax.text(x[0], y[0], " VeriMitigate", color=F.INK, fontsize=6.5, va="bottom")
        ax.set_xscale("log"); ax.set_xticks(x); ax.set_xticklabels([f"{k}x" for k in x])
        ax.set_xlabel("Synthesis speed-up vs GTX 1060"); ax.set_ylabel(lab)
        ax.set_ylim(0, max(max(y), ref) * 1.2)
    fig.tight_layout()
    F.save(fig, os.path.join(OUT, "fig_speed.pdf"))
    for k, t_, r_, c_ in zip(x, ttm, res, col):
        mac(f"speedTtm{['one','two','five','ten','twenty'][[1,2,5,10,20].index(k)]}", f"{t_:.1f}")
        mac(f"speedRes{['one','two','five','ten','twenty'][[1,2,5,10,20].index(k)]}", f"{r_:.1f}")
        mac(f"speedColl{['one','two','five','ten','twenty'][[1,2,5,10,20].index(k)]}", f"{c_:.2f}")
    mac("speedVtTtm", f"{np.median(vt.ttm_c):.1f}"); mac("speedVtRes", f"{100 * vt.residual.mean():.1f}")
    mac("speedCollMin", f"{min(col):.2f}"); mac("speedCollMax", f"{max(col):.2f}")
    mac("speedVtColl", f"{100 * vt.collateral.mean():.2f}")


def a4_macros(main):
    """Run-time verification of an unadapted base model (A4): verified vs unverified, paired, seeds 0-2."""
    try:
        ab = A.flat_A(A.load("A_abl"))
    except FileNotFoundError:
        return
    d = pd.concat([ab, main]); d = d[d.seed < 3]
    for r, k in [("llm_base_fewshot", "U"), ("vm_base_fewshot", "V")]:
        x = d[d.resp == r]
        if x.empty: return
        mac(f"aFour{k}Coll", pct(x.collateral.mean(), 2)); mac(f"aFour{k}Prot", pct(x.prot_avail.mean()))
        mac(f"aFour{k}Mit", pct(x.mitigated.mean())); mac(f"aFour{k}Ttm", f"{np.median(x.ttm_c):.1f}")
        mac(f"aFour{k}Res", pct(x.residual.mean())); mac(f"aFour{k}Hij", pct(x[x.attack == 'Hijack'].collateral.mean(), 1))
        mac(f"aFour{k}Fb", pct(np.nanmean(x.fallback)))
    for met, k in [("collateral", "Coll"), ("prot_avail", "Prot")]:
        t = A.paired(d, "vm_base_fewshot", "llm_base_fewshot", met)
        mac(f"aFourP{k}", f"{t['p']:.1e}".replace("e-0", r"\times10^{-").replace("e-", r"\times10^{-") + "}")
        mac(f"aFourR{k}", f"{t['rbc']:+.2f}")
    mac("aFourN", str(len(d[d.resp == "vm_base_fewshot"])))
    rows = [r for r in A.load("A_abl") if r["resp"] == "vm_base_fewshot" and r["seed"] < 3]
    rej = collections.Counter(x for r in rows for i in r["incidents"] for x in (i["rejects"] or []))
    mac("aFourRejSyntax", str(rej.get("syntax", 0))); mac("aFourRejReach", str(rej.get("reachability", 0)))
    mac("aFourRejTwin", str(rej.get("twin", 0)))


def validation_grid():
    """Synthesizer selection grid (training topologies, seeds 300-302)."""
    try:
        v = A.flat_A(A.load("A_val"))
    except FileNotFoundError:
        return
    L = [r"\begin{table}[h]", r"\centering",
         r"\caption{Synthesizer selection on the training topologies (fresh seeds 300--302; not used for any other result). The selection rule---higher mitigation rate, then lower median TTM---was fixed before the grid was run. DPO-v2 was trained on preferences labelled by the first twin version, which over-credited rate limits.}",
         r"\label{tab:val_sel}", r"\footnotesize", r"\begin{tabular}{lcccccc}", r"\toprule",
         r"Synthesizer & Mitig.\ (\%) & TTM (s) & Residual (\%) & Collateral (\%) & First-try (\%) & Injection / Linkfab mitig.\ (\%) \\", r"\midrule"]
    for r, lab, k in [("vm_sft_val", "SFT (selected)", "Sft"), ("vm_dpo", "SFT + DPO (verifier reward)", "Dpo"),
                      ("vm_dpo2", "SFT + DPO-v2 (flawed reward)", "Dpotwo")]:
        d = v[v.resp == r]
        if d.empty: continue
        inj = 100 * d[d.attack == "Injection"].mitigated.mean(); lf = 100 * d[d.attack == "Linkfab"].mitigated.mean()
        L.append(f"{lab} & {pct(d.mitigated.mean())} & {np.median(d.ttm_c):.1f} & {pct(d.residual.mean())} & "
                 f"{pct(d.collateral.mean(), 2)} & {pct(np.nanmean(d.first_try))} & {inj:.0f} / {lf:.0f} " + r"\\")
        mac(f"valsel{k}Mit", pct(d.mitigated.mean())); mac(f"valsel{k}Inj", f"{inj:.0f}"); mac(f"valsel{k}Lf", f"{lf:.0f}")
        mac(f"valsel{k}Ttm", f"{np.median(d.ttm_c):.1f}")
    L += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    open(os.path.join(OUT, "tab_valsel.tex"), "w").write("\n".join(L) + "\n")


def main():
    df, rows = load_main()
    validation_grid(); a4_macros(df)
    speed(df)
    table_main(df); table_tests(df); table_class(df); table_topo(df); fig_tradeoff(df)
    m1_m4(); table_ablation(df); table_latency(rows); rejections(rows); seen_unseen(df); det_ablation()
    fpinc = df[df.resp != "none"].groupby("resp").fp_incidents.mean()
    mac("fpIncPerRun", f"{fpinc.mean():.2f}")
    c = json.load(open(os.path.join(A.RES, "latency_calib.json")))
    mac("LatA", f"{c['a']:.3f}"); mac("LatB", f"{c['b']:.4f}"); mac("LatC", f"{c['c']:.3f}"); mac("LatRtwo", f"{c['r2']:.3f}")
    mac("nRunsMain", str(len(rows)))
    with open(os.path.join(OUT, "numbers_A.tex"), "w") as f:
        for k, v in sorted(MAC.items()):
            k2 = "".join(ch for ch in k if ch.isalpha())
            f.write(f"\\newcommand{{\\{k2}}}{{{v}}}\n")
    print(json.dumps(MAC, indent=0)[:3000])


if __name__ == "__main__":
    main()
