"""Flow-level detector trained on the real LAN-SDN-NIDS dataset (doi:10.21950/QMAXKP).

Leave-one-topology-out (LOTO): for a simulated run on topology T the detector is
trained on the other four dataset topologies, and every flow record the simulator
emits is a real, held-out record from topology T.  Detector errors inside the
closed loop are therefore the real errors of a real classifier on unseen data.
"""
import json, time, os, pickle
import numpy as np, pandas as pd
import xgboost as xgb
from sklearn.metrics import f1_score, classification_report, confusion_matrix

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data", "FULL_SDN_NIDS.parquet")
OUT = os.path.join(ROOT, "results", "detector")
CLASSES = ["Normal", "Linkfab", "Injection", "Hijack", "DDoS", "PortScan"]
TOPOS = ["Linear", "Tree", "Star", "Mesh", "Subnets"]
CAT = ["last_layer", "eth_type", "OFpredominant_type"]
CP_FEATS = ["OFqty", "OFqty_packetin", "OF_flow_mod", "OFpredominant_type", "OFpredominant_qty",
            "OF_first_seen_delay", "OF_activity_per_s", "OF_to_packet_ratio", "OF_to_byte_ratio",
            "OF_packetin_ratio", "new_mac_ratio"]
# simulator topology -> dataset topology whose held-out records it replays
SIM2DS = {"linear": "Linear", "tree": "Tree", "star": "Star", "mesh": "Mesh",
          "subnets": "Subnets", "iot": "Subnets"}


def load():
    d = pd.read_parquet(DATA)
    d["y"] = d.label.map({c: i for i, c in enumerate(CLASSES)})
    return d


def featurize(d, cats, variant="full"):
    X = d.drop(columns=["label", "topology", "y"])
    if variant == "dataplane":
        X = X.drop(columns=CP_FEATS)
    for c in CAT:
        if c in X.columns:
            X[c] = pd.Categorical(X[c], categories=cats[c])
    return X


def train_loto(d, held, variant="full", seed=0):
    cats = {c: sorted(d[c].unique()) for c in CAT}
    tr = d[d.topology != held]
    # down-sample Normal to 10x the largest attack class to keep training fast; class weights
    rng = np.random.RandomState(seed)
    nmax = tr[tr.y != 0].y.value_counts().max()
    norm = tr[tr.y == 0]
    norm = norm.iloc[rng.choice(len(norm), min(len(norm), 20 * nmax), replace=False)]
    tr = pd.concat([norm, tr[tr.y != 0]])
    Xtr = featurize(tr, cats, variant)
    w = tr.y.map(len(tr) / (len(CLASSES) * tr.y.value_counts())).values
    clf = xgb.XGBClassifier(n_estimators=300, max_depth=8, learning_rate=0.1, subsample=0.8,
                            colsample_bytree=0.8, tree_method="hist", enable_categorical=True,
                            n_jobs=8, random_state=seed)
    clf.fit(Xtr, tr.y.values, sample_weight=w)
    return clf, cats


def main():
    os.makedirs(OUT, exist_ok=True)
    d = load()
    summary = {}
    for variant in ["full", "dataplane"]:
        for held in TOPOS:
            t0 = time.time()
            clf, cats = train_loto(d, held, variant)
            te = d[d.topology == held]
            Xte = featurize(te, cats, variant)
            t1 = time.time()
            P = clf.predict_proba(Xte)
            inf_ms = (time.time() - t1) / len(te) * 1e3
            pred = P.argmax(1)
            f1m = f1_score(te.y, pred, average="macro")
            f1c = f1_score(te.y, pred, average=None, labels=range(6))
            fpr = float((pred[te.y.values == 0] != 0).mean())
            summary[f"{variant}/{held}"] = dict(macro_f1=float(f1m), per_class_f1=dict(zip(CLASSES, map(float, f1c))),
                                                normal_fpr=fpr, infer_ms_per_record=inf_ms,
                                                train_s=t1 - t0,
                                                cm=confusion_matrix(te.y, pred, labels=range(6)).tolist())
            print(variant, held, round(f1m, 4), "FPR", round(fpr, 5), [round(x, 3) for x in f1c], flush=True)
            # store per-record probabilities of held-out topology for the simulator
            np.save(os.path.join(OUT, f"proba_{variant}_{held}.npy"), P.astype(np.float32))
            pickle.dump(clf, open(os.path.join(OUT, f"xgb_{variant}_{held}.pkl"), "wb"))
    json.dump(summary, open(os.path.join(OUT, "loto_summary.json"), "w"), indent=1)
    # record index per topology for the simulator (label + last_layer)
    d[["topology", "label", "last_layer"]].to_parquet(os.path.join(OUT, "record_index.parquet"))


if __name__ == "__main__":
    main()
