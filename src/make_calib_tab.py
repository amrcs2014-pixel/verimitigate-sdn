import json
c = json.load(open('../results/latency_calib.json'))
L = [r"\begin{table}[h]", r"\centering",
     r"\caption{Single-request synthesis latency on the GTX~1060 (fp16 weights, fp32 prefill) used to fit $t=a+b\,n_\mathrm{in}+c\,n_\mathrm{out}$ (" +
     f"$a={c['a']:.3f}$\\,s, $b={c['b']:.4f}$\\,s, $c={c['c']:.3f}$\\,s, $R^2={c['r2']:.3f}$" +
     r"); each configuration was timed three times after a warm-up generation.}",
     r"\label{tab:calib}", r"\footnotesize", r"\begin{tabular}{rrr}", r"\toprule",
     r"Prompt tokens $n_\mathrm{in}$ & Output tokens $n_\mathrm{out}$ & Latency (s) \\", r"\midrule"]
for a, b, t in c['rows']:
    L.append(f"{a} & {b} & {t:.2f} " + r"\\")
L += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
open('../paperA_srep/tab_calib.tex', 'w', newline='\n').write("\n".join(L) + "\n")
