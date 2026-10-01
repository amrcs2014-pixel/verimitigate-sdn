"""Wrap every generated tabular in adjustbox{max width=\\textwidth}: shrinks only tables that are too wide."""
import glob, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BS = "\\"
OPEN = BS + "begin{adjustbox}{max width=" + BS + "textwidth}\n"
CLOSE = "\n" + BS + "end{adjustbox}"
n = 0
for p in glob.glob(os.path.join(ROOT, "paper*_srep", "tab_*.tex")):
    s = open(p, encoding="utf-8").read()
    if "adjustbox" in s or BS + "begin{tabular}" not in s:
        continue
    i = s.index(BS + "begin{tabular}")
    j = s.index(BS + "end{tabular}") + len(BS + "end{tabular}")
    s = s[:i] + OPEN + s[i:j] + CLOSE + s[j:]
    open(p, "w", encoding="utf-8").write(s)
    n += 1
print("wrapped", n)
