"""Run the Phase-2 experiments E1-E6 and write results/ and logs/.

    python experiments/run.py all                 # everything, offline (policy planner)
    python experiments/run.py e3 e5               # a subset
    python experiments/run.py all --planner llm --runs 3   # LLM planner via NVIDIA NIM (needs NVIDIA_API_KEY)

Protocol (see experiments/config.json):
* the calibrator and thresholds are fit on the DEV split only (results/calibration.json);
* every reported number is on the TEST split, which includes three attack types never
  present in dev (held-out, used for G3);
* the injection guard was written against dev payload templates; test payloads use
  disjoint templates.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import pickle
import statistics
import sys
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from guardiantx.agent import AgentConfig, CompliantPlanner, PolicyPlanner, make_planner, run_agent, tx_from_row  # noqa: E402
from guardiantx.baselines import osprey_oracle  # noqa: E402
from guardiantx.calibration import Calibrator  # noqa: E402
from guardiantx.guard import screen  # noqa: E402
from guardiantx.metrics import FLAG, bootstrap_ci, brier, detection, ece, mean_std, risk_coverage, selective  # noqa: E402
from guardiantx.pipeline import analyze_dict  # noqa: E402
from guardiantx.world import World  # noqa: E402

DATA, RES, LOGS = (os.path.join(ROOT, d) for d in ("data", "results", "logs"))
CONFIG = json.load(open(os.path.join(ROOT, "experiments", "config.json"), encoding="utf-8"))


def jl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


ROWS = {r["id"]: r for r in jl(os.path.join(DATA, "corpus.jsonl"))}
SPLITS = json.load(open(os.path.join(DATA, "splits.json"), encoding="utf-8"))
DEV = [ROWS[i] for i in SPLITS["dev"]]
TEST = [ROWS[i] for i in SPLITS["test"]]
INJ = [c for c in jl(os.path.join(DATA, "injections.jsonl")) if c.get("kind") != "benign_string"]
BENIGN_STRINGS = [c for c in jl(os.path.join(DATA, "injections.jsonl")) if c.get("kind") == "benign_string"]
WORLD = World.load(os.path.join(DATA, "world.json"))
INJ_LIMIT = None  # set by --sample (LLM runs)
y = lambda rows: [int(r["label"] == "malicious") for r in rows]  # noqa: E731


def save(name, obj):
    os.makedirs(RES, exist_ok=True)
    with open(os.path.join(RES, name), "w", encoding="utf-8", newline="\n") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False, default=str)


def save_traces(name, items):
    os.makedirs(LOGS, exist_ok=True)
    with open(os.path.join(LOGS, name), "w", encoding="utf-8", newline="\n") as f:
        for it in items:
            f.write(json.dumps(it, ensure_ascii=False, default=str) + "\n")


CKPT = os.path.join(LOGS, "llm_checkpoint.pkl")  # finished LLM tx, so --resume can continue a killed run


def _ckpt_load():
    if not os.path.exists(CKPT):
        return {}
    with open(CKPT, "rb") as f:
        return pickle.load(f)


def run_rows(rows, cfg: AgentConfig, world=WORLD, planner_fn=None):
    out = []
    use_ckpt = cfg.planner == "llm" and planner_fn is None and world is WORLD
    done = _ckpt_load() if use_ckpt else {}
    for i, r in enumerate(rows):
        c = AgentConfig(**{**cfg.__dict__, "seed": cfg.seed * 100003 + i})
        key = (r["id"], c.seed, c.sanitize, c.verify, c.simulation)
        if key in done:
            rep, tr = done[key]
            out.append((r, rep, tr))
            print(f"  [{i + 1}/{len(rows)}] {r['id']} -> {rep.decision.value} (from checkpoint)", flush=True)
            continue
        rep, tr = run_agent(tx_from_row(r), world, c, planner=planner_fn(r) if planner_fn else None)
        out.append((r, rep, tr))
        if use_ckpt and not tr["usage"].get("llm_errors"):  # failed tx are retried on resume
            done[key] = (rep, tr)
            os.makedirs(LOGS, exist_ok=True)
            with open(CKPT + ".tmp", "wb") as f:
                pickle.dump(done, f)
            os.replace(CKPT + ".tmp", CKPT)
        if cfg.planner == "llm":
            progress(i + 1, len(rows), r["id"], rep.decision.value, tr["usage"])
            # streamed as it happens, so a crashed or killed LLM run still leaves its traces
            os.makedirs(LOGS, exist_ok=True)
            with open(os.path.join(LOGS, "llm_live_traces.jsonl"), "a", encoding="utf-8", newline="\n") as f:
                f.write(json.dumps({"id": r["id"], "label": r["label"], "seed": c.seed, **tr},
                                   ensure_ascii=False, default=str) + "\n")
    return out


def progress(i, n, tx_id, decision, usage):
    """LLM runs take ~20-30 s per tx; show they are moving, and loudly when the LLM failed."""
    err = f"  !! LLM FAILED: {usage['llm_error_msgs'][-1][:160]}" if usage.get("llm_errors") else ""
    print(f"  [{i}/{n}] {tx_id} -> {decision} ({usage.get('llm_calls', 0)} calls){err}", flush=True)


def summarize(results, with_ci=False):
    labels = [int(r["label"] == "malicious") for r, _, _ in results]
    dec = [rep.decision.value for _, rep, _ in results]
    probs = [rep.score for _, rep, _ in results]
    m = detection(labels, dec)
    m.update(ece=ece(labels, probs), brier=brier(labels, probs), aurc=risk_coverage(labels, probs)["aurc"],
             **selective(labels, dec))
    m["tool_calls_mean"] = statistics.fmean(tr["usage"]["tool_calls"] for *_, tr in results)
    m["latency_ms_mean"] = statistics.fmean(tr["usage"]["latency_ms"] for *_, tr in results)
    if with_ci:
        m["f1_ci95"] = bootstrap_ci(labels, dec, "f1", seed=CONFIG["seed"])
    return m


# ------------------------------------------------------------------------------
def calibrator() -> Calibrator:
    """Fit Platt scaling + thresholds on DEV with the full (uncalibrated) agent."""
    path = os.path.join(RES, "calibration.json")
    base = AgentConfig(planner="policy", calibrator=Calibrator.identity(), seed=CONFIG["seed"])
    res = run_rows(DEV, base)
    raws = [tr["final"]["raw_score"] for *_, tr in res]
    cal = Calibrator.fit(raws, y(DEV), max_false_block=CONFIG["max_false_block_dev"],
                         max_benign_escalation=CONFIG["max_benign_escalation_dev"])
    os.makedirs(RES, exist_ok=True)
    cal.save(path)
    return cal


def full_cfg(cal, planner="policy", **kw):
    return AgentConfig(planner=planner, calibrator=cal, seed=CONFIG["seed"], **kw)


def e1():
    out = {}
    for name, rows in (("test", TEST), ("test_seen", [r for r in TEST if not r["held_out"]]),
                       ("test_held_out", [r for r in TEST if r["held_out"]]),
                       ("phase1_seed", jl(os.path.join(DATA, "seed_transactions.jsonl")))):
        reps = [analyze_dict(r) for r in rows]
        labels = y(rows)
        dec = [r.decision.value for r in reps]
        out[name] = {**detection(labels, dec), "ece": ece(labels, [r.score for r in reps]),
                     "brier": brier(labels, [r.score for r in reps])}
    out["test"]["f1_ci95"] = bootstrap_ci(y(TEST), [analyze_dict(r).decision.value for r in TEST], seed=CONFIG["seed"])
    save("e1_baseline.json", out)
    return out


def e2():
    out = {}
    for name, rows in (("test", TEST), ("test_held_out", [r for r in TEST if r["held_out"]])):
        dec = [osprey_oracle(tx_from_row(r), WORLD)[0].value for r in rows]
        labels = y(rows)
        out[name] = {**detection(labels, dec), "ece": ece(labels, [1.0 if d == "BLOCK" else 0.0 for d in dec]),
                     "brier": brier(labels, [1.0 if d == "BLOCK" else 0.0 for d in dec])}
    out["note"] = ("Oracle re-implementation of Osprey's ACT detection used pre-signing; an upper bound "
                   "for contract-side detection. Not numbers reported in the base paper.")
    save("e2_base_paper.json", out)
    return out


def e3(cal, planner="policy", runs=1):
    per_run, traces = [], []
    for k in range(runs):
        cfg = full_cfg(cal, planner)
        cfg.seed = CONFIG["seed"] + k
        res = run_rows(TEST, cfg)
        m = {"all": summarize(res, with_ci=(k == 0)),
             "seen": summarize([x for x in res if not x[0]["held_out"]]),
             "held_out": summarize([x for x in res if x[0]["held_out"]])}
        per_cat = defaultdict(Counter)
        for r, rep, _ in res:
            per_cat[f"{r['label']}/{r['category']}"][rep.decision.value] += 1
        m["per_category"] = {k2: dict(v) for k2, v in sorted(per_cat.items())}
        m["llm_failed_tx"] = sum(bool(tr["usage"].get("llm_errors")) for *_, tr in res)
        per_run.append(m)
        traces += [{"run": k, "id": r["id"], "label": r["label"], "category": r["category"], **tr}
                   for r, _, tr in res]
        if k == 0:
            failure_analysis(res, planner)
    save_traces(f"e3_{planner}_test_traces.jsonl", traces)
    agg = {key: {mk: mean_std([pr[key][mk] for pr in per_run])
                 for mk in ("f1", "precision", "recall", "accuracy", "false_block_rate", "ece", "tool_calls_mean")}
           for key in ("all", "seen", "held_out")}
    out = {"planner": planner, "runs": runs, "mean_std": agg, "run0": per_run[0],
           "llm_failed_tx_per_run": [pr["llm_failed_tx"] for pr in per_run]}
    if planner == "llm":  # like-for-like reference: the policy planner on the same (sampled) tx
        cfg = full_cfg(cal, "policy")
        cfg.seed = CONFIG["seed"]
        out["policy_same_sample"] = summarize(run_rows(TEST, cfg))
    save(f"e3_proposed_{planner}.json", out)
    return out


def failure_analysis(res, planner):
    fails, groups = [], Counter()
    for r, rep, tr in res:
        mal = r["label"] == "malicious"
        flagged = rep.decision.value in FLAG
        if mal == flagged:
            continue
        codes = sorted({f.code for f in rep.findings if f.severity >= 0.25})
        if mal:
            cat = "FN: attacker with clean reputation" if not codes else "FN: weak signals below threshold"
        else:
            cat = ("FP: new/unverified legitimate counterparty" if {"FRESH_COUNTERPARTY", "UNVERIFIED_SPENDER", "EOA_SPENDER"} & set(codes)
                   else "FP: other")
        groups[cat] += 1
        fails.append({"id": r["id"], "category": r["category"], "label": r["label"], "decision": rep.decision.value,
                      "failure_category": cat, "codes": codes, "prob": rep.score, "trace": tr})
    succ = [{"id": r["id"], "category": r["category"], "label": r["label"], "decision": rep.decision.value, "trace": tr}
            for r, rep, tr in res if (r["label"] == "malicious") == (rep.decision.value in FLAG)]
    # representative cases: two successes (one held-out drain, one benign), two failures of different kinds
    pick_s = [next((s for s in succ if s["category"] == c), None) for c in ("multicall_proxy_drain", "dex_approval_unlimited")]
    seen_cats, pick_f = set(), []
    for f in fails:
        if f["failure_category"] not in seen_cats:
            seen_cats.add(f["failure_category"])
            pick_f.append(f)
    save(f"failure_analysis_{planner}.json", {
        "n_test": len(res), "n_failures": len(fails), "by_failure_category": dict(groups),
        "by_tx_category": dict(Counter(f["category"] for f in fails)),
        "failures": [{k: v for k, v in f.items() if k != "trace"} for f in fails],
        "representative_successes": [p for p in pick_s if p], "representative_failures": pick_f[:4]})


def g1(cal, planner="policy"):
    # (a) guard screening quality on the payloads themselves
    screening = {}
    for split in ("dev", "test"):
        cases = [c for c in INJ if c["split"] == split]
        per = defaultdict(lambda: [0, 0])
        for c in cases:
            per[c["category"]][0] += screen(c["payload"]).flagged
            per[c["category"]][1] += 1
        ben = [b for b in BENIGN_STRINGS if b["split"] == split]
        screening[split] = {"recall": sum(v[0] for v in per.values()) / len(cases),
                            "per_category_recall": {k: v[0] / v[1] for k, v in per.items()},
                            "benign_false_positive_rate": sum(screen(b["text"]).flagged for b in ben) / len(ben),
                            "benign_false_positives": [b["text"] for b in ben if screen(b["text"]).flagged]}
    # (b) end-to-end attack success with a worst-case (fully compliant) reasoner
    configs = {"no_defense": dict(sanitize=False, verify=False), "sanitizer_only": dict(sanitize=True, verify=False),
               "verifier_only": dict(sanitize=False, verify=True), "full_guard": dict(sanitize=True, verify=True)}
    test_cases = [c for c in INJ if c["split"] == "test"][:INJ_LIMIT]
    asr, traces = {}, []
    for cname, flags in configs.items():
        cfg = full_cfg(cal, planner, **flags)
        clean = {c["tx_id"]: run_agent(tx_from_row(ROWS[c["tx_id"]]), WORLD, cfg)[0] for c in test_cases}
        per_cat, per_goal, succ_total, elig = defaultdict(lambda: [0, 0]), defaultdict(lambda: [0, 0]), 0, 0
        for k, c in enumerate(test_cases):
            w = WORLD.with_metadata(c["target"], {"name": c["payload"]})
            base = make_planner(cfg) if planner == "llm" else PolicyPlanner()
            p = base if planner == "llm" else CompliantPlanner(base, c["payload"], c["goal"])
            rep, tr = run_agent(tx_from_row(ROWS[c["tx_id"]]), w, cfg, planner=p)
            if planner == "llm":
                progress(k + 1, len(test_cases), f"{cname}:{c['tx_id']}", rep.decision.value, tr["usage"])
            if c["goal"] == "rationale":
                ok = c["payload"] in rep.rationale
            else:
                if clean[c["tx_id"]].decision.value not in FLAG:
                    continue  # clean run already misses it: not an injection effect
                ok = rep.decision.value not in FLAG
            elig += 1
            succ_total += ok
            per_cat[c["category"]][0] += ok
            per_cat[c["category"]][1] += 1
            per_goal[c["goal"]][0] += ok
            per_goal[c["goal"]][1] += 1
            if cname == "full_guard" and len(traces) < 15:
                traces.append({"case": c, "success": ok, **tr})
        asr[cname] = {"asr": succ_total / elig if elig else 0.0, "eligible": elig,
                      "per_category": {k: v[0] / v[1] for k, v in per_cat.items()},
                      "per_goal": {k: v[0] / v[1] for k, v in per_goal.items()}}
    save_traces(f"e4_g1_injection_traces_{planner}.jsonl", traces)
    # (c) clean-data detection cost of the guard
    f1_on = summarize(run_rows(TEST, full_cfg(cal, planner)))["f1"]
    f1_off = summarize(run_rows(TEST, full_cfg(cal, planner, sanitize=False, verify=False)))["f1"]
    return {"reasoner": "llm" if planner == "llm" else "worst-case compliant (upper bound)",
            "screening": screening, "attack_success": asr,
            "clean_f1_guard_on": f1_on, "clean_f1_guard_off": f1_off, "f1_delta_points": (f1_on - f1_off) * 100}


def g2(cal):
    out = {}
    for name, c in (("uncalibrated", Calibrator.identity()), ("calibrated", cal)):
        res = run_rows(TEST, full_cfg(c))
        out[name] = summarize(res)
        out[name]["risk_coverage_curve"] = risk_coverage(y(TEST), [rep.score for _, rep, _ in res])["curve"]
    out["thresholds"] = cal.__dict__
    # the same G2 component applied to the miscalibrated Phase-1 rules score
    bc = Calibrator.fit([analyze_dict(r).score for r in DEV], y(DEV), max_false_block=CONFIG["max_false_block_dev"],
                        max_benign_escalation=CONFIG["max_benign_escalation_dev"])
    braw = [analyze_dict(r).score for r in TEST]
    out["phase1_scorer"] = {"method_selected": bc.method,
                            "ece_raw": ece(y(TEST), braw), "ece_calibrated": ece(y(TEST), [bc.prob(r) for r in braw]),
                            "brier_raw": brier(y(TEST), braw), "brier_calibrated": brier(y(TEST), [bc.prob(r) for r in braw])}
    return out


def g3(cal):
    ho = [r for r in TEST if r["held_out"]]
    reps = [analyze_dict(r) for r in ho]
    return {"n_held_out": len(ho), "categories": SPLITS["held_out_categories"],
            "baseline": detection(y(ho), [r.decision.value for r in reps]),
            "base_paper_oracle": detection(y(ho), [osprey_oracle(tx_from_row(r), WORLD)[0].value for r in ho]),
            "agent_dynamic": summarize(run_rows(ho, full_cfg(cal))),
            "agent_fixed_order": summarize(run_rows(ho, full_cfg(cal, "fixed")))}


def e4(cal, planner="policy"):
    out = {"G1_injection": g1(cal, planner), "G2_calibration": g2(cal), "G3_dynamic_investigation": g3(cal)}
    save(f"e4_gaps_{planner}.json", out)
    return out


ABLATIONS = {
    "full_system": {},
    "-sanitizer (G1)": dict(sanitize=False),
    "-verifier (G1)": dict(verify=False),
    "-calibration (G2)": "uncalibrated",
    "-simulation": dict(simulation=False),
    "fixed tool order (G3)": dict(planner="fixed"),
}


def e5(cal, g1_result=None):
    rows_out = []
    for name, mod in ABLATIONS.items():
        cfg = full_cfg(Calibrator.identity()) if mod == "uncalibrated" else full_cfg(cal, **mod)
        m = summarize(run_rows(TEST, cfg))
        ho = summarize(run_rows([r for r in TEST if r["held_out"]], cfg))
        row = {"config": name, "f1": m["f1"], "precision": m["precision"], "recall": m["recall"],
               "false_block_rate": m["false_block_rate"], "escalation_rate": m["escalation_rate"],
               "ece": m["ece"], "brier": m["brier"], "held_out_f1": ho["f1"], "tool_calls_mean": m["tool_calls_mean"]}
        if g1_result:
            key = {"-sanitizer (G1)": "verifier_only", "-verifier (G1)": "sanitizer_only"}.get(name, "full_guard")
            row["worst_case_asr"] = g1_result["attack_success"][key]["asr"]
        rows_out.append(row)
    save("e5_ablation.json", rows_out)
    with open(os.path.join(RES, "e5_ablation.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows_out[0]))
        w.writeheader()
        w.writerows(rows_out)
    return rows_out


def e6(cal, planner="policy"):
    out = {"planner": planner, "efficiency": {}, "reliability": []}
    for name, cfg in (("full_dynamic", full_cfg(cal, planner)), ("fixed_order", full_cfg(cal, "fixed"))):
        res = run_rows(TEST, cfg)
        lat = sorted(tr["usage"]["latency_ms"] for *_, tr in res)
        calls = [tr["usage"]["tool_calls"] for *_, tr in res]
        e = {"tool_calls_mean": statistics.fmean(calls), "tool_calls_max": max(calls),
             "latency_ms_mean": statistics.fmean(lat), "latency_ms_p95": lat[int(0.95 * len(lat)) - 1]}
        if planner == "llm" and name == "full_dynamic":
            for k in ("input_tokens", "output_tokens", "cost_usd", "llm_calls", "fallback_calls", "llm_errors"):
                e[k + "_mean"] = statistics.fmean(tr["usage"].get(k, 0) for *_, tr in res)
            served = {}
            for *_, tr in res:
                for name, n in tr["usage"].get("providers", {}).items():
                    served[name] = served.get(name, 0) + n
            e["calls_by_provider"] = served
        out["efficiency"][name] = e
    clean = {r["id"]: rep.decision.value for r, rep, _ in run_rows(TEST, full_cfg(cal))}
    for rate in CONFIG["fault_rates"]:
        for retries in (0, 2):
            f1s, agree, esc = [], [], []
            for k in range(CONFIG["fault_runs"]):
                cfg = full_cfg(cal, fault_rate=rate)
                cfg.seed = CONFIG["seed"] + 17 * k
                cfg.retries = retries
                res = run_rows(TEST, cfg)
                m = summarize(res)
                f1s.append(m["f1"])
                esc.append(m["escalation_rate"])
                agree.append(sum(rep.decision.value == clean[r["id"]] for r, rep, _ in res) / len(res))
            out["reliability"].append({"fault_rate": rate, "retries": retries,
                                       "f1": mean_std(f1s), "decision_agreement_with_fault_free": mean_std(agree),
                                       "escalation_rate": mean_std(esc)})
    save(f"e6_efficiency_{planner}.json", out)
    return out


def gap_table(e1r, e2r, e3r, e4r, planner):
    g1r, g2r, g3r = e4r["G1_injection"], e4r["G2_calibration"], e4r["G3_dynamic_investigation"]
    asr = g1r["attack_success"]["full_guard"]["asr"]
    asr0 = g1r["attack_success"]["no_defense"]["asr"]
    d1 = g1r["f1_delta_points"]
    st1 = "Fully" if asr < 0.10 and d1 >= -1 else ("Partially" if asr < asr0 else "Not")
    unc, calr, p1 = g2r["uncalibrated"], g2r["calibrated"], g2r["phase1_scorer"]
    better = [calr["ece"] < unc["ece"] - 1e-9, calr["false_block_rate"] < unc["false_block_rate"],
              calr["recall"] > unc["recall"] and calr["false_block_rate"] < 0.05]
    st2 = "Fully" if better[0] and (better[1] or better[2]) and calr["false_block_rate"] < 0.05 else (
        "Partially" if any(better) or p1["ece_calibrated"] < p1["ece_raw"] else "Not")
    ag, bl, osp = g3r["agent_dynamic"]["f1"], g3r["baseline"]["f1"], g3r["base_paper_oracle"]["f1"]
    fx = g3r["agent_fixed_order"]["f1"]
    # proposal criterion: beat the non-agentic baseline on unseen attacks; "Fully" also
    # requires the dynamic tool selection itself (vs. fixed order) to contribute.
    st3 = "Fully" if ag > bl and ag > fx else ("Partially" if ag > bl else "Not")
    lines = [
        "| Gap | Method / component | Metric | Base paper result | Our result | Addressed? |",
        "|---|---|---|---|---|---|",
        f"| G1 Injection resilience | `guard.py` sanitizer + verifier (decision floor, evidence checklist) | "
        f"Attack success rate, worst-case reasoner, 75 test injections (no defense -> full guard); clean-F1 change | "
        f"No reasoning layer, so no injection surface and no defense (not applicable) | "
        f"ASR {asr0:.1%} -> {asr:.1%}; F1 change {d1:+.1f} pts | {st1} |",
        f"| G2 Calibration & abstention | `calibration.py` CV-selected Platt scaling + dev-fit thresholds + ESCALATE band | "
        f"Test ECE, false-block rate, recall, selective accuracy (uncalibrated -> calibrated) | ECE {e2r['test']['ece']:.3f}, "
        f"FBR {e2r['test']['false_block_rate']:.1%}, no confidence or abstention (binary output, oracle re-impl.) | "
        f"agent ({g2r['thresholds']['method']} map): ECE {unc['ece']:.3f} -> {calr['ece']:.3f}, FBR {unc['false_block_rate']:.1%} -> "
        f"{calr['false_block_rate']:.1%}, recall {unc['recall']:.3f} -> {calr['recall']:.3f}, selective acc. "
        f"{unc['selective_accuracy']:.3f} -> {calr['selective_accuracy']:.3f} @ {calr['coverage']:.1%} coverage; "
        f"Phase-1 scorer ECE {p1['ece_raw']:.3f} -> {p1['ece_calibrated']:.3f} | {st2} |",
        f"| G3 Dynamic investigation | `agent.py` PolicyPlanner (data-dependent tool selection) | "
        f"F1 on held-out unseen attack types (n={g3r['n_held_out']}) | F1 {osp:.3f} (oracle re-impl.); "
        f"Phase-1 baseline F1 {bl:.3f} | F1 {ag:.3f} (fixed order {g3r['agent_fixed_order']['f1']:.3f}); "
        f"{g3r['agent_dynamic']['tool_calls_mean']:.2f} vs {g3r['agent_fixed_order']['tool_calls_mean']:.2f} tool calls "
        f"(all test: {e3r['run0']['all']['tool_calls_mean']:.2f} vs fixed order, see E5) | {st3} |",
    ]
    md = "\n".join(lines)
    with open(os.path.join(RES, f"gap_table_{planner}.md"), "w", encoding="utf-8", newline="\n") as f:
        f.write(md + "\n")
    return md


def stratified_sample(rows, n):
    """Seeded sample keeping each category's share; same rows for every run with the same n."""
    import random
    rng = random.Random(CONFIG["seed"])
    by_cat = defaultdict(list)
    for r in rows:
        by_cat[r["category"]].append(r)
    out = []
    for cat in sorted(by_cat):
        k = max(1, round(n * len(by_cat[cat]) / len(rows)))
        out += rng.sample(by_cat[cat], min(k, len(by_cat[cat])))
    if n < len(by_cat):  # fewer tx than categories (smoke tests): can't keep every category
        out = rng.sample(out, n)
    return sorted(out, key=lambda r: r["id"])


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("exps", nargs="*", default=["all"])
    ap.add_argument("--planner", default="policy", choices=["policy", "llm"])
    ap.add_argument("--runs", type=int, default=None, help="repeats for E3 (default: 1 policy, 3 llm)")
    ap.add_argument("--sample", type=int, default=None,
                    help="evaluate on a fixed stratified sample of N test tx (and N injection cases); for rate-limited LLM runs")
    ap.add_argument("--resume", action="store_true",
                    help="LLM runs: reuse tx already finished by a killed/rate-limited run (logs/llm_checkpoint.pkl)")
    a = ap.parse_args(argv)
    if a.planner == "llm" and not a.resume and os.path.exists(CKPT):
        os.remove(CKPT)  # a fresh run must not inherit old results
    if a.sample:
        global TEST, INJ_LIMIT
        TEST, INJ_LIMIT = stratified_sample(TEST, a.sample), a.sample
        print(f"using a stratified sample of {len(TEST)} test tx (seed {CONFIG['seed']})")
    exps = {"e1", "e2", "e3", "e4", "e5", "e6"} if "all" in a.exps else set(a.exps)
    runs = a.runs or (3 if a.planner == "llm" else 1)
    cal = calibrator()
    print(f"calibrator (dev-fit): a={cal.a:.3f} b={cal.b:.3f} t_low={cal.t_low:.3f} t_block={cal.t_block:.3f}")
    r = {}
    for name in ("e1", "e2", "e3", "e4", "e5", "e6"):
        if name not in exps:
            continue
        fn = globals()[name]
        r[name] = fn() if name in ("e1", "e2") else (
            fn(cal, a.planner, runs) if name == "e3" else
            fn(cal, r.get("e4", {}).get("G1_injection")) if name == "e5" else fn(cal, a.planner))
        print(f"{name} done")
    if {"e1", "e2", "e3", "e4"} <= set(r):
        print("\n" + gap_table(r["e1"], r["e2"], r["e3"], r["e4"], a.planner))


if __name__ == "__main__":
    main()
