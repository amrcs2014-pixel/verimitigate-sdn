import json, os
d = json.load(open("../results/detector/loto_summary.json"))
T = ["Linear", "Tree", "Star", "Mesh", "Subnets"]
C = ["Normal", "Linkfab", "Injection", "Hijack", "DDoS", "PortScan"]
L = [r"\begin{table*}[t]", r"\centering",
     r"\caption{Held-out (leave-one-topology-out) detector performance on LAN-SDN-NIDS: per-class F1, macro-F1 and false-positive rate on Normal records (argmax decision). ``Full'' uses all 39 features; ``data-plane'' removes the 11 OpenFlow control-plane features (ablation A6).}",
     r"\label{tab:det}", r"\small", r"\begin{tabular}{llcccccccc}", r"\toprule",
     r"Features & Held-out & " + " & ".join(C) + r" & Macro-F1 & FPR \\", r"\midrule"]
for v, name in [("full", "Full"), ("dataplane", "Data-plane")]:
    for i, t in enumerate(T):
        s = d[f"{v}/{t}"]
        L.append((name if i == 0 else "") + f" & {t} & " + " & ".join(f"{s['per_class_f1'][c]:.3f}" for c in C)
                 + f" & {s['macro_f1']:.3f} & {100*s['normal_fpr']:.2f}\% \\\\")
    if v == "full": L.append(r"\midrule")
L += [r"\bottomrule", r"\end{tabular}", r"\end{table*}"]
open("../paperA/tab_det.tex", "w").write("\n".join(L) + "\n")
print("\n".join(L))
