"""Containernet / Open vSwitch / Ryu validation of the emulator's data-plane predictions -> table + macros."""
import json, os, statistics as st, collections
import analysis as A

CN = os.path.join(A.ROOT, "containernet")
LBL = {"portdrop": "Port-drop", "template": "Template", "vtemplate": "V-Template", "llm": "LLM (unverified)",
       "verimit": "VeriMitigate", "vtemplate_D": "V-Template+D", "verimit_D": "VeriMitigate+D"}


def stats(rows):
    tp = fp = fn = tn = 0
    for r in rows:
        for p, q in zip(r["pred"], r["real"]):
            tp += (not p and not q); fn += (p and not q); fp += (not p and q); tn += (p and q)
    n = tp + fp + fn + tn
    po = (tp + tn) / n
    pe = ((tp + fp) * (tp + fn) + (tn + fn) * (tn + fp)) / n ** 2
    return dict(n=n, agree=po, kappa=(po - pe) / (1 - pe) if pe < 1 else 1.0, tp=tp, fp=fp, fn=fn, tn=tn)


def main():
    R = [json.loads(l) for l in open(os.path.join(CN, "results_real.jsonl"))]
    C = [json.loads(l) for l in open(os.path.join(CN, "results_arpflush.jsonl"))]
    cold = {r["id"]: r for r in C}
    # combined "cold-cache" view: re-run sets replaced by their cold-cache measurement
    Rc = [cold.get(r["id"], r) for r in R]
    s_w, s_c = stats(R), stats(Rc)
    lat = [x for r in R for x in r["install_ms"]]
    M = dict(valSets=str(len(R)), valPairs=f"{s_w['n']:,}".replace(",", "{,}"), valAgree=f"{100 * s_w['agree']:.2f}",
             valKappa=f"{s_w['kappa']:.3f}", valFN=str(s_w["fn"]), valFP=str(s_w["fp"]), valCut=str(s_w["tp"] + s_w["fp"]),
             valColdSets=str(len(C)), valColdAgree=f"{100 * s_c['agree']:.2f}", valColdKappa=f"{s_c['kappa']:.3f}",
             valInstallMed=f"{st.median(lat):.1f}", valInstallP=f"{sorted(lat)[int(0.95 * len(lat))]:.1f}",
             valInstallN=str(len(lat)), valRejected=str(sum(r["rejected"] for r in R)))
    L = [r"\begin{table}[t]", r"\centering",
         r"\caption{Validation on a real data plane: Containernet with Docker hosts, Open vSwitch~2.17 (kernel datapath) and a Ryu controller with the same two-table pipeline. Responder rule sets recorded in the emulator were installed through Ryu's REST interface, and every legitimate (host, service) pair was probed with real TCP/UDP traffic. Agreement: share of pairs whose reachability matched the emulator's prediction; ``missed cuts'': pairs the emulator predicted reachable but the real network cut; ``cold'': the same, with ARP caches flushed before probing.}",
         r"\label{tab:val}", r"\footnotesize", r"\begin{tabular}{lrrrrrr}", r"\toprule",
         r"Responder & Rule sets & Pairs & Agreement (\%) & $\kappa$ & Missed cuts & Agreement, cold (\%) \\", r"\midrule"]
    by = collections.defaultdict(list); byc = collections.defaultdict(list)
    for r, rc in zip(R, Rc): by[r["resp"]].append(r); byc[r["resp"]].append(rc)
    for resp in LBL:
        if resp not in by: continue
        a, c = stats(by[resp]), stats(byc[resp])
        L.append(f"{LBL[resp]} & {len(by[resp])} & {a['n']} & {100 * a['agree']:.2f} & {a['kappa']:.3f} & {a['fn']} & {100 * c['agree']:.2f} " + r"\\")
    L.append(r"\midrule")
    L.append(f"All & {len(R)} & {s_w['n']} & {100 * s_w['agree']:.2f} & {s_w['kappa']:.3f} & {s_w['fn']} & {100 * s_c['agree']:.2f} " + r"\\")
    L += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    os.makedirs(os.path.join(A.ROOT, "paper_outputs"), exist_ok=True)
    for paper in ("paper_outputs",):
        open(os.path.join(A.ROOT, paper, "tab_val.tex"), "w").write("\n".join(L) + "\n")
        with open(os.path.join(A.ROOT, paper, "numbers_val.tex"), "w") as f:
            for k, v in M.items(): f.write(f"\\newcommand{{\\{k}}}{{{v}}}\n")
    print(M)


if __name__ == "__main__":
    main()
