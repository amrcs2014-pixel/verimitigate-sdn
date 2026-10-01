# VeriMitigate: verified language-model mitigation for software-defined IoT networks

Code and complete experiment logs for the paper:

> A. H. Abdelhaliem, *Verification, not generation, makes language-model-driven mitigation safe in software-defined IoT networks* (submitted).

VeriMitigate is a closed detect–explain–mitigate loop for SDN. A detector alert triggers a fine-tuned language model (Qwen2.5-1.5B + LoRA) to write OpenFlow mitigation rules. Before installation, a deterministic verifier checks each rule:

- syntax, OpenFlow prerequisites and class semantics,
- TTL and scope,
- conflicts with installed rules,
- reachability of protected services, including control-plane side effects,
- blast radius.

A traffic-replay twin then confirms the rule stops the attack. Rejected rules return to the model with a concrete counterexample packet.

**Companion repository** (adversarial robustness of automated responders): `sdn-responder-robustness`.

## Key results (reproduced by the logs in `results/`)

| Responder (scenario M0, 150 runs each) | Collateral (benign flows broken by responder rules) |
|---|---|
| Port-drop | 4.60% |
| Classic templates | 3.80% |
| Verified template ladder | 1.34% |
| Fine-tuned LLM, unverified | 0.95% |
| **VeriMitigate** (fine-tuned LLM + verifier + twin) | **0.81%** |
| Unadapted LLM, unverified → verified (ablation A4) | 2.71% → 0.55% |

**Real data-plane validation.** We tested the emulator against Containernet with Open vSwitch 2.17 and Ryu 4.34, using 180 rule sets and 14,292 reachability probes with real TCP/UDP traffic. The two agreed on 99.41% of probes (Cohen's κ = 0.953), and the emulator never missed a cut. Every disagreement came from ARP caching; with cold caches, agreement was 100%.

## Contents

| Path | What it is |
|---|---|
| `src/netsim.py`, `src/sim.py`, `src/scenarios.py` | Flow-level OpenFlow emulator (Ryu-like reactive controller, LLDP discovery, host tracking, security table, meters, capacities), the closed-loop engine and the scenarios |
| `src/detector.py` | Leave-one-topology-out XGBoost detector on LAN-SDN-NIDS; trace-driven detection uses real held-out records |
| `src/verifier.py`, `src/responder.py`, `src/synth.py` | Verifier, twin, counterexample-guided repair, verifier-guided pruning, responders, prompts and templates |
| `src/llm_server.py`, `src/lora.py`, `src/train_lora.py`, `src/sft_data.py`, `src/build_sft.py`, `src/dpo_data.py` | Batched and cached LLM server, LoRA implementation, SFT/DPO training and data builders |
| `src/run_exp.py`, `src/run_all.sh` | Experiment grids (deterministic, resumable) |
| `src/report_A.py`, `src/report_val.py`, `src/analysis.py`, `src/figures.py` | Statistics (bootstrap CIs, paired Wilcoxon with Holm correction, rank-biserial effect sizes), tables and figures |
| `containernet/` | Real data-plane validation: Containernet + OVS + Ryu two-table app `vm_switch.py`, sampled rule sets and probe results |
| `results/*.jsonl` | One JSON line per closed-loop run (metrics, incidents, installed rules) |
| `results/llm_cache.sqlite` | Every LLM completion used, keyed by prompt, so evaluation reproduces exact model outputs without a GPU |
| `results/sft/` | Instruction set, preference pairs and training logs |
| `docs/LAB_NOTEBOOK.md` | Full lab notebook: every step, problem and fix |

### Experiment grids (`results/`)

| File | Content |
|---|---|
| `A_main` | M0: 5 classes × 6 topologies × 5 seeds × 6 responders |
| `A_m1` | Concurrent attacks |
| `A_m4` | Injected detector false positives |
| `A_abl` | Ablations A1–A5 |
| `A_det` | Detector without control-plane features (A6) |
| `A_speed` | Synthesis-speed sensitivity |
| `A_val` | Synthesizer selection on training topologies |

## Reproducing

1. **Setup.** `pip install -r requirements.txt` (Python 3.11).
2. **Data.** Download `FULL_SDN_NIDS.parquet` from LAN-SDN-NIDS (CC BY 4.0, https://doi.org/10.21950/QMAXKP) into `data/`, then run `python src/detector.py`.
3. **Model.** Download `Qwen/Qwen2.5-1.5B-Instruct` into `models/qwen1.5b/`. The selected adapter `sft.pt` is attached to the GitHub Release. To retrain it, run `python src/sft_data.py && python src/build_sft.py && python src/train_lora.py sft --out ../models/adapters/sft.pt --limit 1000` (about 65 min on a GTX 1060).
4. **Experiments.** Run `bash src/run_all.sh`. Every run is a deterministic function of (scenario, topology, seed), and LLM calls are served from `results/llm_cache.sqlite` when present.
5. **Validation** (Ubuntu 22.04, root, with Docker, Open vSwitch, [Containernet](https://github.com/containernet/containernet) and Ryu 4.34 installed):
   1. `python3 containernet/setup_ryu.py && python3 containernet/fix_wsgi.py`
   2. `docker build -t vmval containernet`
   3. `python3 containernet/validate.py`
6. **Tables and figures.** `python src/report_A.py && python src/report_val.py`.

## Licence and citation

- **Code:** MIT. **Logs and derived data:** CC BY 4.0.
- **LAN-SDN-NIDS** and **Qwen2.5** are subject to their own licences and are not redistributed here.
- See `CITATION.cff`, and please also cite the LAN-SDN-NIDS dataset.
