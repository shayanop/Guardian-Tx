"""G1 - injection-resilience layer.

Two independent defenses, each switchable for ablation:

1. **Sanitizer** (`screen`): every untrusted on-chain string (token name, contract
   description, revert reason) is normalised (NFKC, zero-width removal, embedded
   base64 decoding) and scanned against a taxonomy of injection cues covering the
   five categories in the proposal. Flagged text is QUARANTINED: replaced by a
   placeholder before it can reach the reasoner, and the hit itself becomes risk
   evidence (benign contracts have no reason to address the wallet's AI).

2. **Verifier** (`verify`): the reasoner's proposed decision can only *raise* the
   decision computed from trusted evidence, never lower it, and required evidence
   must actually have been collected (otherwise ESCALATE). Its output-provenance
   check (`echoes_untrusted`) drops reasoner text that copies untrusted on-chain
   strings verbatim, so attacker text cannot reach the user through the rationale.
   Both checks are phrasing-independent: they bound what any injection that slips
   past the sanitizer can achieve.

Patterns were written against the DEV injection templates only; TEST templates
are disjoint phrasings (see data/build_corpus.py), so test recall is honest.
"""
from __future__ import annotations

import base64
import difflib
import re
import unicodedata
from dataclasses import dataclass, field

from .contracts import Decision

QUARANTINE = "[quarantined: untrusted text contained instructions]"
_ZERO_WIDTH = re.compile("[​‌‍⁠﻿]")
_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")

# category -> cue regexes (case-insensitive). Phrasings are intentionally about
# *addressing the reader*, not single words, to keep benign names like
# "Override Protocol" or "Safe Token" from tripping them.
CUES: dict[str, list[str]] = {
    "instruction_override": [
        r"\bignore (all |any )?(the )?(previous|prior|above|earlier)\b",
        r"\bdisregard (your|all|the|any)\b", r"\bnew instructions?\b",
        r"\boverride (the |your )?(risk|score|decision|safety)",
        r"\b(must|should) be (approved|allowed)\b", r"\breturn decision\b",
    ],
    "authority_spoofing": [
        r"\bsecurity (team|notice|council)\b", r"\bpassed (an |the )?audit\b",
        r"\bwallets? must\b", r"\bmark (it|this) (as )?safe\b", r"\btrust score\b",
        r"\bsafe to (approve|sign)\b", r"\bconfirms? (this|that|it) (contract )?is safe\b",
    ],
    "tool_output_laundering": [
        r"</?(observation|tool|result)>", r'"(decision|risk|verified|flagged)"\s*:',
        r"\brisk_score\s*=", r"\bsimulation result\b", r"\bno outflows\b",
    ],
    "role_reasoning_spoofing": [
        r"(^|\n)\s*(assistant|system|user)\s*:", r"</?system>", r"(^|\n)\s*thought\s*:",
        r"\baction\s*:\s*finish", r"\bfinal decision\b", r"\byou are now\b",
    ],
    "multilingual_encoded": [
        r"\bignorez\b", r"\binstructions pr[ée]c[ée]dentes\b", r"忽略", r"指令",
        r"\bautorisez\b",
    ],
}
_COMPILED = {c: [re.compile(p, re.IGNORECASE) for p in ps] for c, ps in CUES.items()}


@dataclass
class ScreenResult:
    text: str                      # what the reasoner is allowed to see
    flagged: bool
    categories: list[str] = field(default_factory=list)


def normalize(text: str) -> str:
    t = unicodedata.normalize("NFKC", text)
    t = _ZERO_WIDTH.sub("", t)
    decoded = []
    for m in _B64.findall(t):
        try:
            s = base64.b64decode(m + "=" * (-len(m) % 4), validate=True).decode("utf-8")
            if s.isprintable():
                decoded.append(s)
        except Exception:
            pass
    return " ".join([t, *decoded])


def screen(text: str, limit: int = 300) -> ScreenResult:
    if not text:
        return ScreenResult(text="", flagged=False)
    norm = normalize(text[:limit])
    cats = [c for c, pats in _COMPILED.items() if any(p.search(norm) for p in pats)]
    if cats:
        return ScreenResult(text=QUARANTINE, flagged=True, categories=cats)
    return ScreenResult(text=text[:limit].replace("\u0000", ""), flagged=False)


_ORDER = {Decision.ALLOW: 0, Decision.WARN: 1, Decision.ESCALATE: 2, Decision.BLOCK: 3}


def stricter(a: Decision, b: Decision) -> Decision:
    return a if _ORDER[a] >= _ORDER[b] else b


def verify(evidence_decision: Decision, proposed: Decision | None, missing: list[str]) -> tuple[Decision, list[str]]:
    """Decision floor + required-evidence check. Returns (final decision, notes)."""
    notes = []
    final = evidence_decision
    if proposed is not None:
        if _ORDER[proposed] < _ORDER[evidence_decision]:
            notes.append(f"reasoner proposed {proposed.value} below evidence floor {evidence_decision.value}; clamped")
        final = stricter(evidence_decision, proposed)
    if missing and final != Decision.BLOCK:
        notes.append("required evidence missing: " + ", ".join(missing) + " -> ESCALATE")
        final = stricter(final, Decision.ESCALATE)
    return final, notes


def echoes_untrusted(text: str, untrusted: list[str], min_chars: int = 24) -> bool:
    """True if `text` shares a verbatim span of >= min_chars with any untrusted string."""
    t = normalize(text).lower()
    for u in untrusted:
        u = normalize(u).lower()
        if len(u) < min_chars:
            if len(u) >= 8 and u in t:  # short attacker strings: exact containment only
                return True
            continue
        m = difflib.SequenceMatcher(None, t, u, autojunk=False).find_longest_match(0, len(t), 0, len(u))
        if m.size >= min_chars:
            return True
    return False
