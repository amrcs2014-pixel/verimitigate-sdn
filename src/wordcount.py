"""Approximate word counts of manuscript sections (tables, figures, macros and LaTeX commands removed)."""
import re, os, sys
BS = "\\"


def words(path):
    s = open(path, encoding="utf-8").read()
    tot = 0
    base = os.path.dirname(path)
    for m in re.finditer(re.escape(BS + "input{") + r"([^}]*)\}", s):
        f = m.group(1)
        f = f if f.endswith(".tex") else f + ".tex"
        p = os.path.join(base, f)
        if os.path.exists(p) and not os.path.basename(p).startswith(("tab_", "numbers")):
            tot += words(p)
    t = re.sub(re.escape(BS) + r"begin\{(table|figure)\*?\}.*?" + re.escape(BS) + r"end\{(table|figure)\*?\}", "", s, flags=re.S)
    t = re.sub(re.escape(BS) + r"input\{[^}]*\}", "", t)
    t = re.sub(r"(?<!\\)%.*", "", t)
    t = re.sub(re.escape(BS) + r"[a-zA-Z]+\*?(\[[^\]]*\])?(\{[^}]*\})?", " x ", t)
    return tot + len([w for w in re.split(r"\s+", t) if re.search(r"[A-Za-z0-9]", w)])


root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for p, L in [("paperA_srep", "A"), ("paperB_srep", "B")]:
    parts = {k: words(os.path.join(root, p, f"{k}_{L}.tex")) for k in ["abstract", "intro", "results", "discussion", "methods"]}
    print(p, parts, "main text (I+R+D):", parts["intro"] + parts["results"] + parts["discussion"])
