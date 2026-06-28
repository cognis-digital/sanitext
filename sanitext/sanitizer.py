"""Rule-based sanitization: rewrite text by applying detector replacements."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from . import detectors, lexicons, policies, report


@dataclass(frozen=True)
class Lexicon:
    profanity: dict
    softeners: dict
    slurs: list

    @classmethod
    def default(cls) -> "Lexicon":
        return cls(dict(lexicons.PROFANITY), dict(lexicons.SOFTENERS), list(lexicons.SLURS))

    def merged_with(self, path: str | Path) -> "Lexicon":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        prof = dict(self.profanity)
        prof.update(data.get("profanity", {}))
        soft = dict(self.softeners)
        soft.update(data.get("softeners", {}))
        slurs = list(dict.fromkeys(self.slurs + list(data.get("slurs", []))))
        return Lexicon(prof, soft, slurs)


@dataclass(frozen=True)
class Result:
    clean: str
    report: report.Report

    def to_dict(self) -> dict:
        return {"clean": self.clean, "report": self.report.to_dict()}


def _apply(text: str, findings) -> str:
    out = []
    cursor = 0
    for f in findings:
        out.append(text[cursor:f.start])
        repl = f.replacement
        # Preserve leading capitalization for softened (non-redacted) words.
        if not f.redacted and f.matched[:1].isupper() and repl[:1].islower():
            repl = repl[:1].upper() + repl[1:]
        out.append(repl)
        cursor = f.end
    out.append(text[cursor:])
    return "".join(out)


def sanitize(text: str, *, provider: str = "generic", lexicon: Lexicon | None = None,
             aggressive: bool = False) -> Result:
    """Clean ``text`` using offline rules. Deterministic, no network.

    ``aggressive`` additionally drops any sentence that still contains a
    blocking-category finding after replacement (rare; replacement usually
    suffices), trading completeness for a higher chance of acceptance.
    """
    lex = lexicon or Lexicon.default()
    policy = policies.get(provider)

    source = text
    if aggressive:
        # Drop whole sentences carrying a blocking finding BEFORE redacting, so a
        # leaked secret takes its surrounding sentence with it rather than leaving
        # a "[redacted-secret]" stub behind.
        source = _drop_blocking_sentences(text, lex, policy)

    findings = detectors.detect(source, profanity=lex.profanity, softeners=lex.softeners, slurs=lex.slurs)
    clean = _apply(source, findings)

    # The report describes what was found in the ORIGINAL text and whether that
    # input was acceptable as-is -- the cleaned text is the remediation.
    rep = report.build(
        detectors.detect(text, profanity=lex.profanity, softeners=lex.softeners, slurs=lex.slurs),
        policy,
    )
    return Result(clean=clean, report=rep)


def _drop_blocking_sentences(text: str, lex: Lexicon, policy) -> str:
    import re
    parts = re.split(r"(?<=[.!?])\s+", text)
    kept = []
    for s in parts:
        fs = detectors.detect(s, profanity=lex.profanity, softeners=lex.softeners, slurs=lex.slurs)
        if any(f.category in policy.blocking for f in fs):
            continue
        kept.append(s)
    return " ".join(kept).strip()
