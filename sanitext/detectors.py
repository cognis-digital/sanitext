"""Detectors locate problematic spans in text and classify them.

Each detector yields :class:`Finding` objects with a character span, a category,
a severity, the matched text, and a suggested replacement. The sanitizer uses
the spans+replacements to rewrite; the report uses the categories+severities to
score acceptability.

Categories:
    profanity   - expletives (softened to a neutral word)
    slur        - hateful slur (always redacted)
    hostility   - abusive / toxic phrasing (softened)
    pii         - personal data: email, phone, SSN, IP
    secret      - credentials: API keys, AWS keys, tokens (always redacted)
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from . import lexicons

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class Finding:
    start: int
    end: int
    category: str
    severity: str
    matched: str
    replacement: str
    detector: str

    @property
    def redacted(self) -> bool:
        return self.replacement.startswith("[") and self.replacement.endswith("]")


def _word_pattern(words) -> "re.Pattern[str] | None":
    """Whole-word, case-insensitive alternation over the given words."""
    cleaned = [re.escape(w) for w in words if w]
    if not cleaned:
        return None
    # \b doesn't work well around some symbols; use lookarounds on word chars.
    return re.compile(r"(?<!\w)(" + "|".join(sorted(cleaned, key=len, reverse=True)) + r")(?!\w)", re.IGNORECASE)


# --- PII / secret patterns ---------------------------------------------------

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PHONE = re.compile(r"(?<!\w)(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?!\w)")
_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
# Common credential shapes.
_SECRET_PATTERNS = [
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9]{16,}\b")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{16,}\b")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("generic_bearer", re.compile(r"\b[Bb]earer\s+[A-Za-z0-9._-]{20,}\b")),
]


def _lexicon_findings(text, profanity, softeners, slurs):
    pat = _word_pattern(list(profanity))
    if pat:
        for m in pat.finditer(text):
            repl = profanity.get(m.group(0).lower(), "[removed]")
            yield Finding(m.start(), m.end(), "profanity", "medium", m.group(0), repl, "profanity")

    # Softeners may be multi-word; match them as phrases (case-insensitive).
    for phrase, repl in softeners.items():
        for m in re.finditer(r"(?<!\w)" + re.escape(phrase) + r"(?!\w)", text, re.IGNORECASE):
            sev = "critical" if repl == "[removed]" else "high"
            yield Finding(m.start(), m.end(), "hostility", sev, m.group(0), repl, "softener")

    spat = _word_pattern(slurs)
    if spat:
        for m in spat.finditer(text):
            yield Finding(m.start(), m.end(), "slur", "critical", m.group(0), "[redacted-slur]", "slur")


def _pii_findings(text):
    for m in _EMAIL.finditer(text):
        yield Finding(m.start(), m.end(), "pii", "high", m.group(0), "[redacted-email]", "email")
    for m in _SSN.finditer(text):
        yield Finding(m.start(), m.end(), "pii", "critical", m.group(0), "[redacted-ssn]", "ssn")
    for m in _PHONE.finditer(text):
        # Skip pure digit runs already claimed by SSN; SSN runs first by ordering in detect().
        yield Finding(m.start(), m.end(), "pii", "medium", m.group(0), "[redacted-phone]", "phone")
    for m in _IPV4.finditer(text):
        yield Finding(m.start(), m.end(), "pii", "low", m.group(0), "[redacted-ip]", "ipv4")


def _secret_findings(text):
    for name, pat in _SECRET_PATTERNS:
        for m in pat.finditer(text):
            yield Finding(m.start(), m.end(), "secret", "critical", m.group(0), "[redacted-secret]", name)


def detect(text, *, profanity=None, softeners=None, slurs=None):
    """Return non-overlapping findings, highest severity winning on conflict."""
    profanity = lexicons.PROFANITY if profanity is None else profanity
    softeners = lexicons.SOFTENERS if softeners is None else softeners
    slurs = lexicons.SLURS if slurs is None else slurs

    raw = []
    raw.extend(_secret_findings(text))
    raw.extend(_pii_findings(text))
    raw.extend(_lexicon_findings(text, profanity, softeners, slurs))

    # Resolve overlaps: prefer higher severity, then longer span, then earlier.
    raw.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], -(f.end - f.start), f.start))
    chosen: list[Finding] = []
    for f in raw:
        if any(not (f.end <= c.start or f.start >= c.end) for c in chosen):
            continue
        chosen.append(f)
    chosen.sort(key=lambda f: f.start)
    return chosen
