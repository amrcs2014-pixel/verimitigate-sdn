"""Figures for both papers (matplotlib, print-ready PDF). Palette: validated categorical order,
fixed per responder across all figures; values are direct-labelled (contrast relief)."""
import os, sys, json
import numpy as np, pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import analysis as A

ROOT = A.ROOT
C = {"none": "#8a8985", "portdrop": "#eb6834", "template": "#1baf7a", "vtemplate": "#eda100",
     "vtemplate_D": "#008300", "llm": "#e87ba4", "verimit": "#2a78d6", "verimit_D": "#4a3aa7"}
LBL = {"none": "None", "portdrop": "Port-drop", "template": "Template", "vtemplate": "V-Template",
       "vtemplate_D": "V-Template+D", "llm": "LLM (unverified)", "verimit": "VeriMitigate", "verimit_D": "VeriMitigate+D"}
INK, INK2, GRID = "#0b0b0b", "#52514e", "#e4e3df"

plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 8, "axes.edgecolor": INK2, "axes.labelcolor": INK,
                     "xtick.color": INK2, "ytick.color": INK2, "axes.spines.top": False, "axes.spines.right": False,
                     "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.5, "axes.axisbelow": True,
                     "legend.frameon": False, "pdf.fonttype": 42})


def bars(ax, labels, vals, errs, colors, fmt="{:.1f}", ylabel=""):
    x = np.arange(len(labels))
    b = ax.bar(x, vals, width=0.72, color=colors, edgecolor="white", linewidth=1.0)
    if errs is not None:
        ax.errorbar(x, vals, yerr=errs, fmt="none", ecolor=INK2, elinewidth=0.7, capsize=2)
    top = ax.get_ylim()[1]
    for xi, v, e in zip(x, vals, errs[1] if errs is not None else [0] * len(x)):
        ax.text(xi, v + (e if e == e else 0) + top * 0.025, fmt.format(v), ha="center", va="bottom",
                fontsize=6.5, color=INK)
    ax.set_xticks(x); ax.set_xticklabels(labels, rotation=30, ha="right")
    ax.set_ylabel(ylabel); ax.grid(axis="x", visible=False)
    return b


def ci_arrays(groups, order, metric, scale=1.0):
    m, lo, hi = [], [], []
    for r in order:
        t = A.boot_ci(groups.get_group(r)[metric].values)
        m.append(t[0] * scale); lo.append((t[0] - t[1]) * scale); hi.append((t[2] - t[0]) * scale)
    return np.array(m), np.array([lo, hi])


def save(fig, path):
    fig.savefig(path, bbox_inches="tight"); fig.savefig(path.replace(".pdf", ".png"), dpi=200, bbox_inches="tight")
    plt.close(fig)
