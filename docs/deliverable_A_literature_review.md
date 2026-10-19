# Deliverable A — Literature Review & Research Gaps

> **Note on use.** This is a complete draft written as original synthesis from the
> papers' published abstracts, venue pages, and metadata (no text is copied from
> the papers). Your course bars AI-generated writing, so **rewrite each section in
> your own voice and verify every number against the source PDF before you submit.**
> Items only you can supply (member names/roll numbers, venue-ranking screenshots,
> and P4's full co-author list, which was access-blocked) are marked `[FILL]`.

Project: **GuardianTx** — an injection-resilient, risk-calibrated agent for
pre-signing Ethereum transaction defense.

---

## 1. Base paper and proof of ranking

**N. Ruaro, F. Gritti, D. Meng, R. McLaughlin, I. Grishchenko, C. Kruegel, and
G. Vigna, "Approve Once, Regret Forever: On the Exploitation of Ethereum's
Approve-TransferFrom Ecosystem," *34th USENIX Security Symposium*, 2025,
pp. 1281–1298.**

**Proof of ranking.** USENIX Security is ranked **A\*** on the CORE conference
portal (the top tier), satisfying the "A\*/A conference" requirement for a base
paper. `[FILL: attach a screenshot of the CORE portal entry for "USENIX Security"
in the appendix as proof.]`

**Why we selected it.** This is the most recent top-venue study of the exact
mechanism GuardianTx defends against: the ERC-20 approve → transferFrom pattern
that underlies most token-draining attacks. It gives us a precise threat model, a
concrete system to compare against, and quantified real-world impact, which makes
it the natural anchor for a pre-signing defense project.

**Problem, method, data, results.** The authors formalise a vulnerability class
they call **ACT (Approved Controllable TransferFrom)**: because a token approval
lets an application move a user's tokens, any attacker who can control the
arguments of that application's `transferFrom` call can drain every user who
approved it. To find such bugs at scale they build **Osprey**, a system that
detects ACT-vulnerable contracts and automatically generates proof-of-concept
exploits. Scanning the Ethereum ecosystem, Osprey flags **32,582** potentially
vulnerable contracts, confirms **410** as exploitable, and quantifies over
**$3.4M** of assets immediately at risk, against a vulnerability class already
linked to more than **$65M** in historical losses.

**Limitations (author-stated and ours).** Osprey is a *contract-side, offline*
analysis: it tells a developer or auditor that a contract is vulnerable, but it
does nothing for an ordinary user at the moment they are about to sign a
transaction. It does not produce a per-transaction risk score, it has no notion of
calibrated confidence or human escalation, and it is not concerned with LLM-agent
robustness or prompt injection. These are precisely the openings GuardianTx
targets.

**How GuardianTx builds on and goes beyond it.** We move the defense to the
**user, pre-signing** side; we add **dynamic, multi-tool investigation**
(calldata decoding, simulation, allowance inspection, proxy resolution); we output
a **calibrated risk score with an explicit abstention/escalation band**; and we
make the reasoning layer **resilient to prompt injection** embedded in untrusted
on-chain data — none of which Osprey attempts.

---

## 2. Cross-paper comparison table

Base paper is row 1, marked ★.

| # | Title (short) | Year & Venue | Dataset / Benchmark | Method / Architecture | Eval Metrics | Key Results | Limitation / Gap |
|---|---|---|---|---|---|---|---|
| 1 ★ | Approve Once, Regret Forever (Osprey) | 2025, USENIX Sec (A\*) | Ethereum contracts scan | Static ACT-vuln detection + PoC generation | # vuln / # exploitable / $ at risk | 32,582 flagged, 410 exploitable, >$3.4M | Contract-side, offline; no user-side pre-sign defense |
| 2 | DeepTx | 2025, ASE (Tool Demo) | Authors' phishing tx set | Pre-sign simulation + multi-modal features + multi-LLM consensus + self-reflection | Precision/Recall (no numeric values in abstract) | "high precision/recall" on phishing set | No injection-resilience eval; no calibration; fixed pipeline |
| 3 | Agent Security Bench (ASB) | 2025, ICLR (A\*) | 10 scenarios, 10 agents, 400+ tools | Benchmark of attacks (DPI/IPI/memory/PoT) + 11 defenses, 13 LLMs | Attack success rate (ASR), 7 metrics | Peak avg ASR **84.30%**; defenses limited | General agents, not blockchain/tx; defenses weak |
| 4 | Unmasking the Shadow Economy (Drainer-as-a-Service) | 2025, IMC (ACM) | Ethereum, Mar'23–Apr'25 | Measurement study of DaaS phishing | $ drained, # victims | ~**$135M** drained, **76,582** victims | Measurement only — characterizes, does not defend |
| 5 | Dissecting Payload-based Transaction Phishing | 2025, NDSS (A\*) | Ground-truth + real tx | Rule-based multi-dimensional detection | Accuracy | **>99% accuracy** on ground-truth; 1,726 phishing addresses found | Rule-based (brittle to new patterns); no calibration/abstention |
| 6 | Blockchain Address Poisoning | 2025, USENIX Sec (A\*) | Ethereum+BSC, Jul'22–Jun'24 | Large-scale detection + measurement | # attacks / # victims | **270M** on-chain attacks, **17M** victims (13× prior) | Address-poisoning only; measurement/detection, not pre-sign agent |
| 7 | PROXiFY | 2025, ASE (Tool Demo) | High-confidence proxy benchmark | Bytecode analysis to detect & classify **proxy** contracts (incl. inactive) | Precision / Recall | **98.6% precision, 97.1% recall** | Proxy detection only — one slice of the pre-sign picture |
| 8 | Agent4Vul | 2025, Science China Info. Sci. (Q1) | SC source + bytecode CFG | Multimodal **LLM agents** (comment+vector gen) for vuln detection | F1 | **+3.61–16.32% F1** over AI baselines; beats GPT-4o/o1 | Vuln detection, not tx-time defense; no injection robustness |
| 9 | LLM-SmartAudit (Multi-Agent) | 2025, IEEE TSE (Q1) | Common-vuln benchmark + real-world corpus + CVE set | LLM-powered **multi-agent** vuln detection | Accuracy | **98% acc** on common vulns; **12/13** CVEs found | Audit-time, not pre-sign; no calibration |
| 10 | Smart-LLaMA-DPO | 2025, ISSTA (A\*) | 4 vuln types + unauditable, w/ explanations | LLaMA-3.1-8B: continual pretrain + SFT + **DPO** for explainable detection | F1 / Accuracy (relative) | **+10.43% F1, +7.87% acc** over baselines; faithful explanations | Detection+explanation, not tx risk scoring |
| 11 | Trust or Escalate | 2025, ICLR (A\*) | LLM-judge agreement data | **Abstention** policy via "Simulated Annotators" (confidence = sim agreement) | Human-agreement / selective metrics | predictive-prob **overestimates** agreement | LLM-judge setting, not blockchain risk; motivates escalation |

---

## 3. Critical summaries

### Paper 1 (★ base) — Approve Once, Regret Forever (USENIX Security 2025)
See the full analysis in §1. In brief: Ruaro et al. define the ACT vulnerability
class, in which attacker-controlled `transferFrom` arguments let a malicious party
drain everyone who approved a contract, and build Osprey to detect such contracts
and auto-generate exploits (32,582 flagged, 410 confirmed exploitable, >$3.4M at
risk, against >$65M historical losses). Its limitation — an offline, contract-side
tool with no user-facing, calibrated, injection-aware defense at signing time — is
the gap GuardianTx is designed to fill.

### Paper 2 — DeepTx (ASE 2025, Tool Demonstration)
*Y. Liu, X. Li, Y. Li (Nanyang Technological University).* DeepTx attacks the
problem that Web3 users routinely sign transactions whose intent they cannot read,
which phishing campaigns exploit. The tool simulates a transaction before it is
signed, extracts behavioural, contextual, and user-interface features, and then
has several large language models judge the transaction's intent, resolving
disagreement through consensus and self-reflection; the output is a natural-language
risk report with a severity level, an explanation, and a suggested action. The
authors evaluate it on their own phishing dataset and report high precision and
recall (the abstract gives no numeric figures), releasing code and data publicly.
Its main weaknesses, and the openings for our work, are threefold: the LLMs reason
over *untrusted* on-chain features with **no evaluation of prompt-injection
robustness**; the system produces categorical judgements with **no calibrated
confidence or abstention**; and its feature-extraction-then-LLM pipeline is
**fixed**, with no dynamic decision about which analysis tools to invoke. DeepTx is
the closest existing system to GuardianTx and therefore serves as our primary
comparison baseline, which we aim to surpass on injection resilience, calibration,
and dynamic investigation.

### Paper 3 — Agent Security Bench / ASB (ICLR 2025)
*Zhang et al. (Zhejiang University, Rutgers University).* ASB addresses the absence
of a standard way to measure how attacks and defenses perform against LLM-based
agents. The authors formalise and implement a benchmark spanning direct prompt
injection, indirect prompt injection, memory poisoning, a novel Plan-of-Thought
backdoor, and mixed attacks, together with eleven corresponding defenses, and run
them across thirteen LLM backbones over ten application scenarios and more than
four hundred tools. Their headline result is a **peak average attack success rate
of 84.30%**, with the finding that current defenses are of limited effectiveness.
The benchmark's scope is general-purpose agents rather than blockchain or
transaction-signing settings, it relies largely on fixed injection strings, and
the defenses it surveys remain weak — all caveats we carry into our own design. For
GuardianTx, ASB is the central piece of evidence that *any* LLM-based transaction
analyser will be highly vulnerable to injection unless resilience is engineered in
deliberately, which directly justifies our injection-resilience focus and the
120-case taxonomy we construct for evaluation.

### Paper 4 — Unmasking the Shadow Economy / Drainer-as-a-Service (IMC 2025)
*B. He et al. (Zhejiang University, MBZUAI).* `[FILL: complete co-author list from
the ACM DL page.]` This paper presents the first systematic measurement of the
Drainer-as-a-Service (DaaS) economy on Ethereum, in which professional operators
rent turnkey wallet-draining kits to affiliates in exchange for a share of stolen
funds. Using a snowball-sampling approach seeded from known phishing addresses, the
authors map the full operational pipeline of operators, affiliates, and
profit-sharing, and quantify its scale: roughly **$135M drained from 76,582 victim
wallets** between March 2023 and April 2025, with a common 20%/80% operator-to-
affiliate split. The study is descriptive by design: it characterises and measures
the threat but builds **no defensive mechanism**, leaving the protective response
to others. Its relevance to GuardianTx is twofold: it supplies realistic,
documented attack patterns and scale figures that justify a user-side defense, and
it directly informs the composition of our benign/malicious transaction corpus.

### Paper 5 — Dissecting Payload-based Transaction Phishing (NDSS 2025)
*Z. Chen, Y. Hu, B. He, D. Luo, L. Wu, Y. Zhou.* This work targets phishing that is
carried out through the *payload* of Ethereum transactions — chiefly deceptive
`approve` and `permit` operations — rather than through surface-level social
engineering. The authors propose a rule-based, multi-dimensional detection method
and evaluate it on a ground-truth dataset and on real-world transactions, reporting
**over 99% accuracy** and surfacing 1,726 phishing addresses. (Some secondary
write-ups additionally quote an F1 score and specific rates for phishing among
approve and permit transactions; verify the exact figures in the NDSS version
before citing them.) The method's reliance on hand-crafted rules is also its
limitation: rule sets tend to be brittle against obfuscated or previously unseen
patterns, and the approach offers no confidence calibration, no abstention, and no
defense against adversarial manipulation of the reasoning process. For our project
it is strong prior art on the exact approve/permit surface we guard, and it
anchors two of our gaps — the absence of calibration (G2) and the limits of static
rules relative to a dynamic agent (G3).

### Paper 6 — Blockchain Address Poisoning (USENIX Security 2025)
*T. Tsuchiya, J.-D. Dong, K. Soska, N. Christin.* This paper studies address
poisoning, in which attackers seed a victim's transaction history with transfers
from look-alike addresses (sharing the same leading and trailing characters as a
real counterparty) in the hope the victim later copies the wrong address. The
authors build a detector and run a large-scale measurement across Ethereum and BSC
from July 2022 to June 2024, uncovering roughly **270 million on-chain attack
attempts against about 17 million victims** — some thirteen times more than
previously reported. The work is deliberately focused on a single attack type and
remains a measurement-and-detection study rather than a user-facing, pre-signing
agent. Its relevance to GuardianTx is direct: it both justifies and supplies
ground-truth patterns for the address-poisoning heuristic already implemented in
our baseline, and it quantifies a threat that a pre-signing guard is well placed to
stop at the moment of signing.

### Paper 7 — PROXiFY (ASE 2025, Tool Demonstration)
*I. Qasse, M. Hamdaqa, B. Þ. Jónsson.* PROXiFY is a lightweight, bytecode-based
tool that detects and classifies Ethereum proxy contracts — including *inactive*
ones whose dormant upgrade paths could later be reactivated — without requiring an
Ethereum node, source code, or a customised EVM. The authors argue that prior
approaches depend on source or transaction history and therefore miss inactive
proxies, and they report **98.6% precision and 97.1% recall** on a high-confidence
benchmark. As a single-purpose detector, it addresses only one slice of the
pre-signing picture rather than end-to-end transaction defense. It is nonetheless
highly relevant to GuardianTx: upgradeable proxies can hide the real implementation
a user is actually approving, so robust proxy detection and resolution is exactly
one of the investigative tools our agent needs, and PROXiFY validates that this can
be done accurately from bytecode alone.

### Paper 8 — Agent4Vul (Science China Information Sciences 2025)
*W. Jie, W. Qiu, H. Yang, M. Guo, X. Huang, T. Lei, Q. Zhang, H. Zheng, Z. Zheng.*
Agent4Vul tackles smart-contract vulnerability detection with a multimodal,
agentic LLM design: dedicated LLM agents generate natural-language comments and
feature vectors, which are combined with a multimodal model operating over source
code and bytecode control-flow graphs. The approach reports **F1 improvements of
3.61% to 16.32%** over existing AI baselines and outperforms strong general models
including GPT-4o and o1. Its scope is audit-time contract analysis rather than
transaction-time defense, and it does not address prompt-injection robustness or
calibrated risk. For GuardianTx the paper is useful as evidence that *agentic*,
multi-tool LLM analysis genuinely outperforms single-model approaches on
contract-security tasks, which supports the agentic justification behind our
dynamic-investigation gap (G3).

### Paper 9 — LLM-SmartAudit / Multi-Agent Detection (IEEE TSE 2025)
*Z. Wei, J. Sun, Y. Sun, Y. Liu, D. Wu, Z. Zhang, X. Zhang, M. Li, Y. Liu, C. Li,
M. Wan, J. Dong, L. Zhu.* This work proposes an LLM-powered multi-agent system for
smart-contract vulnerability detection, in which cooperating agents analyse a
contract and aggregate their findings. It is evaluated on a common-vulnerability
benchmark, a real-world project corpus, and a CVE dataset, reporting **98% accuracy
on common vulnerabilities** and identifying **12 of 13 CVEs**, while outperforming
existing tools. Like Agent4Vul it operates at audit time rather than at the point
of signing, and it provides no per-transaction calibrated risk or abstention
mechanism. Its relevance to GuardianTx lies in its demonstration of multi-agent
LLM orchestration for security analysis — prior art on the coordination patterns
our investigative agent builds on for G3.

### Paper 10 — Smart-LLaMA-DPO (ISSTA 2025)
*L. Yu et al. (Institute of Software, Chinese Academy of Sciences).* This paper
observes that LLMs often misread the *order* of state changes in a contract, which
can yield a faithful-looking but wrong explanation even when the final
vulnerable/not-vulnerable verdict is correct. To produce explanations that are both
accurate and trustworthy, the authors fine-tune LLaMA-3.1-8B through a three-stage
pipeline — continual pre-training on contract code, supervised fine-tuning, and
Direct Preference Optimization over paired high- and low-quality explanations —
using a dataset spanning four vulnerability types plus machine-unauditable cases,
with labels, explanations, and vulnerability locations. It reports relative gains of
**+10.43% F1 and +7.87% accuracy** over baselines. Its scope is detection with
explanation rather than transaction risk scoring or abstention. For GuardianTx the
paper matters because our ALLOW/WARN/BLOCK/ESCALATE decisions must come with
*faithful* explanations a user can trust, and Smart-LLaMA-DPO shows both why naive
LLM explanations fail and how preference optimisation can make them reliable.

### Paper 11 — Trust or Escalate (ICLR 2025)
*J. Jung, F. Brahman, Y. Choi (University of Washington, Allen Institute for AI).*
Framed around LLMs acting as evaluative judges, this paper argues such judges
should not be trusted blindly and instead proposes selective evaluation with
provable guarantees of agreement with humans at a user-chosen confidence level. Its
core technique, "Simulated Annotators," estimates confidence from the agreement
among simulated annotator preferences, and a Cascaded Selective Evaluation scheme
starts with cheaper judges and escalates to stronger models only when confidence is
low; the authors show that common confidence signals such as raw predictive
probability tend to **overestimate** true human agreement. The setting is LLM-as-
judge rather than blockchain transaction risk, which bounds its direct
applicability. Its relevance to GuardianTx is methodological and important: it
provides the principled basis for our **ESCALATE** band and our calibration work
(G2), namely the idea that a system should quantify when to trust its own decision
and defer to a human otherwise.

---

## 4. Research-gap synthesis

Across the reviewed work, three specific, evidence-based, and testable gaps emerge
that GuardianTx addresses. Each is grounded in named papers, relates directly to the
base paper, and can be measured within the semester.

**Gap 1 — There is no pre-signing, injection-resilient defense for the human
signer.** Existing work either detects vulnerable *contracts* offline (the base
paper's Osprey), measures the threat after the fact (P4, P6), or analyses
transactions with LLMs but never tests robustness to prompt injection in the
untrusted on-chain data it consumes (P2, DeepTx). ASB (P3) shows that LLM agents
suffer attack success rates around 84%, so an unhardened LLM transaction analyser
would itself be an attack surface. No system today protects a user at the moment of
signing while remaining resilient to injection.

**Gap 2 — Detectors report accuracy but are neither risk-calibrated nor able to
abstain.** The phishing and vulnerability detectors we reviewed — rule-based (P5)
and LLM-based (P2, P8, P10) — report point metrics such as accuracy or F1 with no
expected calibration error, no Brier score, and no principled abstention. "Trust or
Escalate" (P11) shows that LLM confidence tends to overestimate correctness and
motivates escalation, but not in the blockchain-transaction setting. A pre-signing
guard that blocks or allows irreversibly needs a *calibrated* score and an explicit
abstention band.

**Gap 3 — No agent dynamically investigates the full pre-signing context.** Each
prior tool covers only one slice: static contract analysis (P1), hand-crafted rules
(P5), proxy detection alone (P7), or a fixed feature-then-LLM pipeline (P2). None
chooses, per transaction, which tools to run across calldata decoding, simulation,
allowance inspection, and proxy resolution; and none measures tool-use efficiency
against a non-agentic baseline.

| Gap | Supporting evidence (papers) | Proposed approach | How it will be measured |
|---|---|---|---|
| **G1 — No pre-signing, injection-resilient defense for the human signer.** | P1 (base); P2; P3 (ASB, 84% ASR); P4; P6 | A pre-sign agent that decodes/simulates the tx and sanitizes untrusted on-chain text at a defined boundary before any LLM reasoning. | Detection P/R/F1 on benign/malicious tx **+** injection **attack-success-rate** across the 120-case taxonomy (5 categories). |
| **G2 — Detectors report accuracy but are not calibrated and never abstain.** | P5; P2; P8; P10; P11 | Calibrated risk score + principled **ALLOW/WARN/BLOCK/ESCALATE** abstention band. | **ECE**, **Brier score**, **risk–coverage curve**, **false-block rate**, alongside P/R/F1. |
| **G3 — No agent that *dynamically* investigates the full pre-sign context.** | P1; P2; P5; P7; P8/P9 (agentic precedent) | An agent that selects which tools to call per tx (decode, simulate, allowance, proxy), vs. the fixed non-agentic baseline. | Detection vs. baseline; **tool-call efficiency**; latency/cost; performance on **held-out unseen attack types & contract variants**. |

---

## 5. References (IEEE)

> Links were confirmed live. Re-check author lists, page numbers, and DOIs against
> each official PDF before submission; complete item [4]'s co-author list.

[1] N. Ruaro, F. Gritti, D. Meng, R. McLaughlin, I. Grishchenko, C. Kruegel, and G. Vigna, "Approve Once, Regret Forever: On the Exploitation of Ethereum's Approve-TransferFrom Ecosystem," in *Proc. 34th USENIX Security Symp.*, Seattle, WA, USA, 2025, pp. 1281–1298. https://www.usenix.org/conference/usenixsecurity25/presentation/ruaro

[2] Y. Liu, X. Li, and Y. Li, "DeepTx: Real-Time Transaction Risk Analysis via Multi-Modal Features and LLM Reasoning," in *Proc. 40th IEEE/ACM Int. Conf. Automated Software Engineering (ASE), Tool Demonstration Track*, 2025. arXiv:2510.18438. https://arxiv.org/abs/2510.18438

[3] H. Zhang, J. Huang, K. Mei, Y. Yao, Z. Wang, C. Zhan, H. Wang, and Y. Zhang, "Agent Security Bench (ASB): Formalizing and Benchmarking Attacks and Defenses in LLM-based Agents," in *Proc. Int. Conf. Learning Representations (ICLR)*, 2025. arXiv:2410.02644. https://iclr.cc/virtual/2025/poster/29432

[4] B. He *et al.*, "Unmasking the Shadow Economy: A Deep Dive into Drainer-as-a-Service Phishing on Ethereum," in *Proc. ACM Internet Measurement Conf. (IMC)*, 2025, doi: 10.1145/3730567.3764476. https://dl.acm.org/doi/10.1145/3730567.3764476

[5] Z. Chen, Y. Hu, B. He, D. Luo, L. Wu, and Y. Zhou, "Dissecting Payload-based Transaction Phishing on Ethereum," in *Proc. Network and Distributed System Security Symp. (NDSS)*, 2025. arXiv:2409.02386. https://www.ndss-symposium.org/wp-content/uploads/2025-311-paper.pdf

[6] T. Tsuchiya, J.-D. Dong, K. Soska, and N. Christin, "Blockchain Address Poisoning," in *Proc. 34th USENIX Security Symp.*, 2025. arXiv:2501.16681. https://www.usenix.org/system/files/usenixsecurity25-tsuchiya.pdf

[7] I. Qasse, M. Hamdaqa, and B. Þ. Jónsson, "PROXiFY: A Bytecode Analysis Tool for Detecting and Classifying Proxy Contracts in Ethereum Smart Contracts," in *Proc. ASE 2025, Tool Demonstration Track*, 2025. https://conf.researchr.org/details/ase-2025/ase-2025-tool-demonstration-track/37

[8] W. Jie, W. Qiu, H. Yang, M. Guo, X. Huang, T. Lei, Q. Zhang, H. Zheng, and Z. Zheng, "Agent4Vul: Multimodal LLM Agents for Smart Contract Vulnerability Detection," *Science China Information Sciences*, 2025, doi: 10.1007/s11432-024-4402-2. https://link.springer.com/article/10.1007/s11432-024-4402-2

[9] Z. Wei, J. Sun, Y. Sun, Y. Liu, D. Wu, Z. Zhang, X. Zhang, M. Li, Y. Liu, C. Li, M. Wan, J. Dong, and L. Zhu, "Advanced Smart Contract Vulnerability Detection via LLM-Powered Multi-Agent Systems," *IEEE Trans. Software Engineering*, vol. 51, pp. 2830–2846, 2025. https://pure.bit.edu.cn/en/publications/

[10] L. Yu *et al.*, "Smart-LLaMA-DPO: Reinforced Large Language Model for Explainable Smart Contract Vulnerability Detection," *Proc. ACM Software Engineering*, ISSTA 2025, doi: 10.1145/3728878. https://conf.researchr.org/details/issta-2025/issta-2025-papers/9

[11] J. Jung, F. Brahman, and Y. Choi, "Trust or Escalate: LLM Judges with Provable Guarantees for Human Agreement," in *Proc. Int. Conf. Learning Representations (ICLR)*, 2025. arXiv:2407.18370. https://proceedings.iclr.cc/paper_files/paper/2025/hash/08dabd5345b37fffcbe335bd578b15a0-Abstract-Conference.html
