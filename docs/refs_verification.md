# refs_notes.md - verification log

Method: metadata (title, authors, venue, year, pages, DOI) for every entry in refs.bib was confirmed by (a) the Crossref/DataCite DOI-registry record for that DOI, and/or (b) a WebSearch hit on the publisher / arXiv / USENIX / NeurIPS / IETF page, and/or (c) fetching the arXiv abstract page. "Crossref" = api.crossref.org record for the DOI. No entry was written from memory alone. Paper tags: [A]=VeriMitigate, [B]=robustness/adversary paper, [both].
Total entries in refs.bib: 62 (more than the 35-45 target; all verified, prune by tag as needed).

## A. Must-check items from the proposal

- `erol2027sentinellm` - [both] SentineLLM: LLM-based IDS for software-defined IoT; closest prior LLM-IDS in SD-IoT. Record: Expert Systems with Applications vol. 333, art. 134239, issue-dated Jan 2027 (DOI prefix eswa.2026, so online 2026); authors Arife Gulsah Erol, Sedef Demirci - matches proposal apart from the 2027 issue year. VERIFIED (Crossref DOI record): https://doi.org/10.1016/j.eswa.2026.134239
- `arevalo2026multiclass` - [both] LAN-SDN-NIDS paper: multi-class SDN IDS dataset with synchronized OpenFlow control-plane telemetry (Data, MDPI, 11(8), art. 195, 5 Aug 2026). Crossref author 'Torre' has given name 'Jose Ignacio Martinez' (surname ordering not confirmed). VERIFIED (Crossref + WebSearch hit on doi.org page): https://doi.org/10.3390/data11080195
- `arevalo2026lansdnnids` - [both] The dataset record itself (e-cienciaDatos, 2026): 'LAN-SDN-NIDS: A Multi-Class Dataset for OpenFlow Attack Detection'. Proposal DOI 10.21950/QMAXKP is correct; DataCite creator list is partly ORCID-only strings so bib lists first author + 'others'. VERIFIED (DataCite API + doi.org redirect to edatos.consorciomadrono.es): https://doi.org/10.21950/QMAXKP
- `swileh2025unseen` - [both] BERT-based LLM unseen-attack detection in SDN (AI 2025, 6(7), 154). VERIFIED (Crossref + arXiv 2412.06239 + WebSearch): https://doi.org/10.3390/ai6070154
- `swileh2025proactive` - [both] Zero-training LLM DDoS detection+mitigation in decentralized SDN (arXiv only, no journal version found). DIFFERS FROM PROPOSAL: actual arXiv 2511.00460 title is 'Proactive DDoS Detection and Mitigation in Decentralized Software-Defined Networking via Port-Level Monitoring and Zero-Training Large Language Models' (Swileh & Zhang, 1 Nov 2025); mitigation is port-level blocking at the attacker's port, relevant to blast-radius scoping. VERIFIED (arXiv abstract page fetched): https://arxiv.org/abs/2511.00460
- `wang2024shieldgpt` - [A] ShieldGPT: LLM-based DDoS mitigation framework (APNet 2024, pp. 108-114). Title is 'ShieldGPT: An LLM-based Framework for DDoS Mitigation', not 'LLM-assisted'; authors Wang, Xie, Zhang, Wang, Zhang, Cui. VERIFIED (Crossref + WebSearch (ACM DL, APNet PDF)): https://doi.org/10.1145/3663408.3663424
- `elhachimi2025flowrule` - [A] LLM flow-rule generation for SDN with retry-based deployment validation (Ryu/OpenFlow JSON). DIFFERS FROM PROPOSAL: it is NOT an IETF draft. Found as (i) IETF-124 NMRG presentation slides (Nov 2025; datatracker page shows no Internet-Draft) and (ii) a peer-reviewed CNSM 2025 paper (El Hachimi, Di Cicco, Ibrahimi, Musumeci, Tornatore), cited here as the CNSM paper. VERIFIED (Crossref + WebSearch + datatracker slides page https://datatracker.ietf.org/doc/slides-124-nmrg-sessa-flow-rule-generation-for-sdn-using-llms-with-retry-based-deployment-validation/): https://doi.org/10.23919/cnsm67658.2025.11297487
- `li2026controllability` - [B] Controllability-aware adversarial examples vs LLM-based traffic classifiers (arXiv 2607.07739, 8 Jul 2026, author Zhenpeng Li, preprint only; directly/indirectly/un-controllable feature groups). VERIFIED (arXiv abstract page fetched): https://arxiv.org/abs/2607.07739
- `kazemian2012header` - [A] Header Space Analysis (NSDI 2012, pp. 113-126; NSDI'24 Test-of-Time award). No DOI. VERIFIED (WebSearch hit on USENIX page): https://www.usenix.org/conference/nsdi12/technical-sessions/presentation/kazemian
- `alshaer2004discovery` - [A] Firewall policy anomaly taxonomy (shadowing, redundancy, correlation, generalization) for rule-conflict checks (INFOCOM 2004, vol 4, pp. 2605-2616). Crossref gives initials only (E. S. Al-Shaer, H. H. Hamed). VERIFIED (Crossref DOI record): https://doi.org/10.1109/infcom.2004.1354680
- `hong2015poisoning` - [B] Poisoning network visibility in SDN (link fabrication, host location hijacking; TopoGuard) NDSS 2015. VERIFIED (Crossref DOI record): https://doi.org/10.14722/ndss.2015.23283
- `rafailov2023dpo` - [A] DPO preference optimization for LLM fine-tuning. NeurIPS 2023 author order (Rafailov, Sharma, Mitchell, Manning, Ermon, Finn) taken from the NeurIPS proceedings page; arXiv order has Ermon before Manning. VERIFIED (NeurIPS proceedings page fetched + arXiv 2305.18290): https://papers.nips.cc/paper_files/paper/2023/hash/a85b405ed65c6477a4fe8302b5e06ce7-Abstract-Conference.html
- `elsayed2020insdn` - [both] InSDN dataset (IEEE Access vol 8, pp. 165263-165284); authors Elsayed, Le-Khac, Jurcut as in proposal. VERIFIED (Crossref DOI record): https://doi.org/10.1109/access.2020.3022633

## B. Additional references

- `mckeown2008openflow` - [both] OpenFlow (SIGCOMM CCR 38(2):69-74). VERIFIED (Crossref DOI record): https://doi.org/10.1145/1355734.1355746
- `kreutz2015sdn` - [both] SDN survey (Proc. IEEE 103(1):14-76). VERIFIED (Crossref DOI record): https://doi.org/10.1109/jproc.2014.2371999
- `scotthayward2016survey` - [B] Survey of SDN security threats (IEEE COMST 18(1)). VERIFIED (Crossref DOI record): https://doi.org/10.1109/comst.2015.2453114
- `dhawan2015sphinx` - [B] SPHINX, detecting SDN topology/flow-graph attacks (NDSS 2015). VERIFIED (Crossref DOI record): https://doi.org/10.14722/ndss.2015.23064
- `shin2013avantguard` - [B] AVANT-GUARD, data-to-control-plane saturation defense (CCS 2013). VERIFIED (Crossref title+subtitle): https://doi.org/10.1145/2508859.2516684
- `wang2015floodguard` - [B] FloodGuard, DoS prevention for SDN (DSN 2015). VERIFIED (Crossref DOI record): https://doi.org/10.1109/dsn.2015.27
- `skowyra2018tampering` - [B] Topology tampering attacks and defenses (DSN 2018). VERIFIED (Crossref DOI record): https://doi.org/10.1109/dsn.2018.00047
- `xu2017attacking` - [B] Attacking the Brain: races in SDN control plane triggered by external network events (USENIX Sec 2017, pp. 451-468). VERIFIED (WebSearch hit on USENIX page): https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/xu-lei
- `yoon2017flowwars` - [B] Flow Wars: SDN attack-surface systematization incl. flow-rule/table attacks (IEEE/ACM ToN 25(6)). VERIFIED (Crossref DOI record): https://doi.org/10.1109/tnet.2017.2748159
- `porras2012fortnox` - [both] FortNOX security enforcement kernel with flow-rule conflict detection (HotSDN 2012). VERIFIED (Crossref DOI record): https://doi.org/10.1145/2342441.2342466
- `hu2014flowguard` - [A] FlowGuard firewall/flow-rule conflict detection in SDN (HotSDN 2014). VERIFIED (Crossref DOI record): https://doi.org/10.1145/2620728.2620749
- `son2013flover` - [A] Model checking invariant security properties in OpenFlow (ICC 2013); the tool name 'Flover' comes from the proposal and is not in the Crossref title, title/authors/venue are verified. VERIFIED (Crossref DOI record): https://doi.org/10.1109/icc.2013.6654813
- `khurshid2012veriflow` - [A] VeriFlow real-time invariant checking (SIGCOMM CCR 42(4):467-472, 2012 version; NSDI'13 full version not cited). VERIFIED (Crossref DOI record): https://doi.org/10.1145/2377677.2377766
- `kazemian2013netplumber` - [A] NetPlumber, incremental HSA-based policy checking (NSDI 2013). VERIFIED (WebSearch hit on USENIX page): https://www.usenix.org/conference/nsdi13/technical-sessions/presentation/kazemian
- `mai2011anteater` - [A] Anteater data-plane verification (SIGCOMM 2011). VERIFIED (Crossref DOI record): https://doi.org/10.1145/2018436.2018470
- `fogel2015batfish` - [A] Batfish (NSDI 2015, pp. 469-483). VERIFIED (WebSearch hit on USENIX page): https://www.usenix.org/conference/nsdi15/technical-sessions/presentation/fogel
- `monsanto2013pyretic` - [A] Pyretic policy composition (NSDI 2013). VERIFIED (WebSearch hit on USENIX page): https://www.usenix.org/conference/nsdi13/technical-sessions/presentation/monsanto
- `foster2011frenetic` - [A] Frenetic network programming language (ICFP 2011). VERIFIED (Crossref DOI record): https://doi.org/10.1145/2034773.2034812
- `berde2014onos` - [both] ONOS controller (HotSDN 2014). VERIFIED (Crossref DOI record): https://doi.org/10.1145/2620728.2620744
- `lantz2010mininet` - [both] Mininet (HotNets 2010, 'A network in a laptop'). VERIFIED (Crossref DOI record): https://doi.org/10.1145/1868447.1868466
- `peuster2018containernet` - [both] Containernet 2.0 (NetSoft 2018); LAN-SDN-NIDS used Containernet. The 2016 MeDICINE paper (10.1109/nfv-sdn.2016.7919490) also exists in Crossref but is not in refs.bib; whether it is the canonical Containernet citation is UNVERIFIED. VERIFIED (Crossref DOI record): https://doi.org/10.1109/netsoft.2018.8459905
- `wang2024netconfeval` - [A] NetConfEval, LLM network config benchmark (Proc. ACM Netw. 2(CoNEXT2), 2024). VERIFIED (Crossref DOI record): https://doi.org/10.1145/3656296
- `mondal2023routerconfig` - [A] 'What do LLMs need to synthesize correct router configurations?' (HotNets 2023) - closest match to the proposal's 'Verified Prompt Programming'; that alias itself was not confirmed. VERIFIED (Crossref DOI record): https://doi.org/10.1145/3626111.3628194
- `tang2021campion` - [A] Campion, router config differencing (SIGCOMM 2021). VERIFIED (Crossref DOI record): https://doi.org/10.1145/3452296.3472925
- `tang2023lightyear` - [A] Lightyear modular BGP control-plane verification (SIGCOMM 2023). VERIFIED (Crossref DOI record): https://doi.org/10.1145/3603269.3604842
- `wu2024netllm` - [A] NetLLM adapting LLMs for networking tasks (SIGCOMM 2024). VERIFIED (Crossref DOI record): https://doi.org/10.1145/3651890.3672268
- `huang2025llmnetworking` - [A] LLMs for networking overview (IEEE Network 39(1)). VERIFIED (Crossref DOI record): https://doi.org/10.1109/mnet.2024.3435752
- `bui2024llmids` - [A] Systematic comparison of LLMs for intrusion detection (Proc. ACM Netw. 2(CoNEXT4), 2024). VERIFIED (Crossref DOI record): https://doi.org/10.1145/3696379
- `apruzzese2022modeling` - [B] Realistic adversarial attacks vs NIDS (DTRAP 3(3), 2022). VERIFIED (Crossref DOI record): https://doi.org/10.1145/3469659
- `sheatsley2022adversarial` - [B] Adversarial examples for NIDS (J. Computer Security 30(5), 2022). VERIFIED (Crossref DOI record): https://doi.org/10.3233/jcs-210094
- `pierazzi2020problemspace` - [B] Problem-space adversarial attacks (IEEE S&P 2020). VERIFIED (Crossref DOI record): https://doi.org/10.1109/sp40000.2020.00073
- `aiken2019adversarial` - [B] Adversarial attacks vs NIDS in SDNs (NFV-SDN 2019). VERIFIED (Crossref DOI record): https://doi.org/10.1109/nfv-sdn47374.2019.9040101
- `kang2013crossfire` - [B] Crossfire link-flooding attack (IEEE S&P 2013); attacker exploits defender/routing behaviour. VERIFIED (Crossref DOI record): https://doi.org/10.1109/sp.2013.19
- `toth2002response` - [B] Impact/collateral cost of automated intrusion response (ACSAC 2002; year inferred from conference name, Crossref lacks date). VERIFIED (Crossref DOI record): https://doi.org/10.1109/csac.2002.1176302
- `lee2002costsensitive` - [B] Cost-sensitive intrusion detection and response (J. Computer Security 10(1-2)). VERIFIED (Crossref DOI record): https://doi.org/10.3233/jcs-2002-101-202
- `axelsson2000baserate` - [B] Base-rate fallacy in IDS (ACM TISSEC 3(3)); supports evidence thresholding. VERIFIED (Crossref DOI record): https://doi.org/10.1145/357830.357849
- `lichtblau2017spoofed` - [B] Measurement of spoofed-source traffic in the Internet (IMC 2017); supports spoofed-identifier threat model. VERIFIED (Crossref DOI record): https://doi.org/10.1145/3131365.3131367
- `ferguson2000ingress` - [B] RFC 2827 / BCP 38 ingress filtering vs source spoofing. VERIFIED (RFC text fetched): https://www.rfc-editor.org/rfc/rfc2827
- `greshake2023indirect` - [B] Indirect prompt injection into LLM-integrated apps (AISec 2023); attacker-controlled data reaching an LLM. VERIFIED (Crossref + arXiv 2302.12173): https://doi.org/10.1145/3605764.3623985
- `hu2022lora` - [A] LoRA (ICLR 2022). VERIFIED (WebSearch hit on OpenReview/ICLR pages + arXiv 2106.09685 fetched): https://openreview.net/forum?id=nZeVKeeFYf9
- `qwen2024qwen25` - [A] Qwen2.5 Technical Report (arXiv 2412.15115, Dec 2024; author list is 'Qwen' + team, truncated with 'others'). VERIFIED (arXiv abstract page fetched): https://arxiv.org/abs/2412.15115
- `chen2016xgboost` - [both] XGBoost (KDD 2016, pp. 785-794). VERIFIED (Crossref DOI record): https://doi.org/10.1145/2939672.2939785
- `holm1979simple` - [both] Holm sequentially rejective multiple-test correction (Scand. J. Statist. 6(2):65-70, 1979). No DOI in Crossref; JSTOR page failed to load in WebFetch, so confirmed only via WebSearch secondary listings (Semantic Scholar / BibSonomy / BibBase) that cite JSTOR stable id 4615733. VERIFIED (secondary listings only): https://www.jstor.org/stable/4615733
- `wilcoxon1945ranking` - [both] Wilcoxon signed-rank test (Biometrics Bulletin 1(6):80-83). VERIFIED (Crossref DOI record): https://doi.org/10.2307/3001968
- `efron1979bootstrap` - [both] Bootstrap (Ann. Statist. 7(1), 1979; pages omitted, not returned by Crossref). VERIFIED (Crossref DOI record): https://doi.org/10.1214/aos/1176344552
- `vargha2000cles` - [both] Vargha-Delaney A12 effect size (JEBS 25(2):101-132). VERIFIED (Crossref DOI record): https://doi.org/10.3102/10769986025002101
- `cliff1993dominance` - [both] Cliff's delta (Psych. Bulletin 114(3):494-509). VERIFIED (Crossref DOI record): https://doi.org/10.1037/0033-2909.114.3.494
- `wu2021digitaltwin` - [A] Digital twin networks survey (IEEE IoT-J 8(18), 2021). VERIFIED (Crossref DOI record): https://doi.org/10.1109/jiot.2021.3079510
- `bera2017sdniot` - [both] SDN for IoT survey (IEEE IoT-J 4(6), 2017). VERIFIED (Crossref DOI record): https://doi.org/10.1109/jiot.2017.2746186

## C. UNVERIFIED / not included in refs.bib

- Ryu controller: no canonical peer-reviewed paper located (project docs only); cite as software/URL. UNVERIFIED.
- "Verified Prompt Programming": no paper by that exact title found; closest is `mondal2023routerconfig`. Alias UNVERIFIED.
- El Hachimi IETF NMRG *draft*: no Internet-Draft found; only IETF-124 slides + CNSM 2025 paper. Draft claim UNVERIFIED.
- Swileh & Zhang title "Zero-training LLM-based DDoS detection and mitigation in decentralized SDN": exact title not found; arXiv 2511.00460 has a different title. Journal version UNVERIFIED.
- Dedicated papers on "Denial of service via automated response", "Poisoning attacks against intrusion response", fail2ban/blocklist abuse via spoofed sources: searches returned only blog/news material and RFC 2827; no peer-reviewed paper located. UNVERIFIED (not in bib). Closest verified support: toth2002response, kang2013crossfire, lichtblau2017spoofed, ferguson2000ingress, hong2015poisoning.
- Stand-alone TCAM/flow-table exhaustion paper: one candidate (Shen et al., Applied Sciences 2023, 10.3390/app13127210) appeared in Crossref but was not added; saturation attacks are covered via shin2013avantguard, wang2015floodguard, yoon2017flowwars.
- Not searched: SDN-specific ML-IDS survey beyond those found (candidates seen only as search-result titles, e.g. Xie et al. COMST 2019 10.1109/comst.2018.2866942, Yan et al. COMST 2016 10.1109/comst.2015.2487361 - Crossref-visible but not added to bib).
- Most DOI entries were confirmed at DOI-registry (Crossref) level; publisher landing pages were not opened individually.
