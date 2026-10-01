# VeriMitigate (Paper A) + Responder Robustness (Paper B) — pipeline state

Last saved: 2026-09-30 ~09:20

## Layout
- `data/` LAN-SDN-NIDS (FULL_SDN_NIDS.parquet, readme, data dictionary; CC BY 4.0, doi:10.21950/QMAXKP)
- `models/qwen1.5b/` Qwen2.5-1.5B-Instruct; `models/adapters/sft.pt` LoRA SFT adapter (done)
- `src/` all code:
  - `detector.py` LOTO XGBoost (done → `results/detector/`)
  - `netsim.py` flow-level OpenFlow emulator; `sim.py` closed-loop engine; `scenarios.py`
  - `verifier.py` 6-check verifier; `synth.py` prompts/templates; `responder.py` R1–R5 + defenses
  - `llm_server.py` batched cached GPU server (`python llm_server.py --adapters sft=../models/adapters/sft.pt,dpo=../models/adapters/dpo.pt`)
  - `lora.py`, `train_lora.py` (sft|dpo), `sft_data.py`, `build_sft.py`, `dpo_data.py`
  - `run_exp.py <grid> [--only resp,...] [--workers N]` resumable → `results/<grid>.jsonl`
  - `analysis.py`, `figures.py`, `tab_det.py`
- `paperA/` IEEE TNSM LaTeX (main.tex, body_A.tex written; results/discussion/abstract pending)
- `paperB/` Computers & Security LaTeX (main.tex, body_B.tex written; results pending)
- `refs.bib` (62 verified refs), `refs_notes.md` (verification log)

## Done
1. Detector LOTO (macro-F1 0.82–0.96 full; 0.72–0.84 data-plane only)
2. Latency calibration GTX 1060: t = -0.17 + 0.0032 n_in + 0.164 n_out (R²=0.999)
3. Non-LLM grids complete: A_main, A_m1, A_m4, A_det, B_main, B_none, B_cost (none/portdrop/template/vtemplate/vtemplate_D)
4. SFT data (1574 ex) + LoRA SFT (1000 ex, 65 min, loss 0.003) → models/adapters/sft.pt

## Done (cont.)
5. DPO: 185 pairs (11 on-policy + 174 template), 46 steps, loss 0.006 → models/adapters/dpo.pt

## In progress / next
6. RUNNING: `src/run_llm_all.sh` (phases: merged-DPO server → all DPO grids; merged-SFT → A_abl vm_sft; base → A_abl base variants).
   Log: results/run_llm_all.log. Resumable: just rerun `./run_llm_all.sh` from src/ (kill stray python first).
   LLM max_new_tokens = 110; B_main LLM responders use seeds 0-2 (--maxseed 3); A_m4 LLM = verimit, verimit_D.
7. `python report_A.py` / `python report_B.py` → tables, figures, numbers_*.tex in paperA/ paperB/
8. Write results_*.tex, abstract_*.tex, discussion_*.tex, conclusion_*.tex; compile with pdflatex+bibtex; render-check

## Note (13:00): DPO v1 broke format adherence
- dpo_v1_broken.pt (lr 5e-5, no anchor): schema-valid 16/25 on held-out training prompts (Injection 1/5, Linkfab 0/5) vs SFT 25/25.
  Cause: likelihood displacement on mostly off-policy template pairs. A_main LLM rows from it were deleted.
- dpo2.pt: lr 1e-5 + NLL anchor on chosen (--nll 1.0). Check in results/sft/check_dpo2.txt. All configs now use adapter "dpo2".
- Merged-adapter serving verified identical to on-the-fly LoRA (SFT 25/25 both).

## Note (14:00): twin meter bug fixed
- Twin used to count any meter as blocking 50% (= acceptance threshold) → ineffective 1 Mbit/s meters on ARP/LLDP floods were accepted.
  Fixed: meter blocked fraction = 1 - rate/offered_kbps (same model as live network); history entries carry offered kbps.
- All verified-responder rows (vtemplate, vtemplate_D, llm, verimit, verimit_D) deleted and non-LLM ones rerun.
- Synthesizer selection: grid A_val (training topologies, seeds 300-302) compares vm_sft vs verimit(dpo2); rule fixed in advance:
  higher mitigation rate, then lower median TTM. Winner becomes VeriMitigate's adapter; run_llm_all.sh then reruns LLM grids.

## Note (14:45): synthesizer selection
- A_val (training topologies, seeds 300-302): vm_sft_val mitig 93.3% / TTM 17.6 s vs vm_dpo2 68.3% / 21.2 s → SFT selected (pre-declared rule).
- DPO2 failed because its preference data was labelled by the buggy (meter-crediting) twin → learned ineffective meters ("reward hacking a flawed verifier").
- DPO3: data regenerated with fixed twin (records_v1/sft_train_v1 etc. backed up; SFT itself unchanged), train → dpo3.pt, validate via A_val vm_dpo.
- All main configs now adapter="sft"; A5 ablation = vm_dpo (dpo3). run_llm_all.sh rewritten (phases sft → dpo3 → base).

## Note (19:00): format + Paper B harm attribution
- User asked for Scientific Reports format: new folders paperA_srep/, paperB_srep/ (main.tex uses ../scirep_style.tex, naturemag.bst).
  report_A.py / report_B.py now write into *_srep folders.
- Paper B metric fix: harm is attributed per rule -> incident; amplification/downtime now count only rules installed for
  incidents triggered by attack traffic (FP-triggered harm reported separately: lost_bytes_rule_fp, host_down_rule_fp).
  B_main/B_abl/B_stale will be re-run by src/rerun_B.sh (auto-chained after ALLDONE via chain_B.sh; old rows -> *_v1.jsonl).
- New grid A_speed (synthesis latency /2,/5,/10,/20) for Paper A.
- Pipelines are launched DETACHED (Start-Process) so they survive session ends. Logs: results/run_llm_all.log, results/rerun_B.log

## Note (22:30): DETERMINISM FIX + FULL RE-RUN
- Bug: scenarios used Python hash() (salted per process) -> same seed gave different scenarios in different workers
  (not reproducible; "matched" pairs not truly matched). Also: link-set order (shortest-path ties), global Rule id counter,
  measured verifier/twin time in the schedule.
- Fixes: zlib.crc32 stable seeds; sorted links; Rule ids reset per run; fixed charged verifier cost (20 ms, measured value
  logged as verify_meas) and twin 1 s (twin_meas logged). Verified identical outputs across PYTHONHASHSEED values.
- Old results moved to results/archive_nondeterministic/. LLM cache kept (keys = exact prompts).
- RUNNING (detached): src/full_rerun.sh -> results/full_rerun.log (phases: non-LLM, SFT, base, DPO3, DPO2; prints ALLDONE).
- After ALLDONE: python report_A.py; python report_B.py; rebuild paperA_srep/paperB_srep; re-check every sentence against numbers.

## Note (03:10): Containernet validation DONE + remaining
- WSL Ubuntu-22.04: docker.io 29, OVS 2.17 (kernel), Containernet (pip from /opt/containernet), Ryu 4.34 (+eventlet 0.33.3,
  wsgi ALREADY_HANDLED patch, dnspython>=2.2), bridge-nf-call-* = 0. Image vmval:latest. Scripts in containernet/.
- 180 rule sets, 14,292 pair probes: 99.41% agreement, kappa 0.953, 0 missed cuts; 84 disagreements all ARP-cache related,
  cold-cache re-run 956/956 (100%). Install latency median 18.1 ms, p95 50 ms. -> src/report_val.py -> tab_val.tex, numbers_val.tex
- A4 (base model) trimmed to vm_base_fewshot vs llm_base_fewshot, seeds 0-2: src/base_run.sh (auto after ALLDONE; log results/base_run.log, BASEDONE)
- Paper texts in paperA_srep/ paperB_srep/ (Scientific Reports format). Final: rerun report_A/report_B/report_val, write A4/A5 paragraph
  (results_A_part3b.tex), adjust Paper A framing, compile, render-check.

## FINAL (05:30, 1 Oct 2026): COMPLETE
- All grids deterministic and complete; Containernet validation complete; A4/A5 done.
- Manuscripts (Scientific Reports format) built by work/build.sh; packaged by src/package.py into ../Final/
  (PDF, SI PDF, self-contained LaTeX + zip per paper), Final/Q1_Assessment_AR.md, Final/README.md.
