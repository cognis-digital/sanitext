"""Top-level scan / clean API centered on the Unicode-security engine.

This is the flagship entry point. :func:`scan` inspects text for Unicode abuses
(bidi/Trojan-Source, zero-width, control chars, homoglyphs) and, optionally,
PII/secrets, returning a :class:`ScanResult` with structured findings, a cleaned
string, and helpers for JSON / SARIF / human reports.

Example
-------
>>> from sanitext import scan, clean
>>> r = scan("hi​there")          # zero-width space smuggled in
>>> r.dangerous
True
>>> [f.category for f in r.unicode_findings]
['zero_width']
>>> clean("hi​there")
'hithere'
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import detectors, unicode_scan
from .detectors import Finding
from .unicode_scan import UFinding, UnicodeScanOptions

# Unicode categories that make text "dangerous" (should fail a CI gate).
_DANGEROUS_UNICODE = {
    unicode_scan.CAT_BIDI,
    unicode_scan.CAT_ZERO_WIDTH,
    unicode_scan.CAT_INVISIBLE,
    unicode_scan.CAT_CONTROL,
}


@dataclass(frozen=True)
class ScanOptions:
    """What to scan for. Unicode-security checks are on by default; PII is opt-in
    for scanning but its findings never fail the CI gate unless requested."""

    unicode: UnicodeScanOptions = field(default_factory=UnicodeScanOptions)
    pii: bool = True  # scan for PII/secrets and report them
    # Whether homoglyphs count toward the "dangerous" gate (default: no; they
    # are reported but a homoglyph alone is often benign in prose).
    homoglyph_is_dangerous: bool = False


@dataclass(frozen=True)
class ScanResult:
    """Outcome of a scan: structured findings + a cleaned rendering."""

    source: str
    clean: str
    unicode_findings: list[UFinding]
    pii_findings: list[Finding]

    @property
    def findings(self) -> list[UFinding]:
        """Alias for the headline (Unicode-security) findings."""
        return self.unicode_findings

    @property
    def dangerous(self) -> bool:
        """True if any dangerous Unicode finding is present (CI-gate signal)."""
        return any(f.category in _DANGEROUS_UNICODE for f in self.unicode_findings)

    def counts(self) -> dict[str, int]:
        c: dict[str, int] = {}
        for f in self.unicode_findings:
            c[f.category] = c.get(f.category, 0) + 1
        for f in self.pii_findings:
            key = f"pii:{f.category}" if f.category == "pii" else f.category
            c[key] = c.get(key, 0) + 1
        return c

    def to_dict(self) -> dict:
        return {
            "dangerous": self.dangerous,
            "counts": self.counts(),
            "clean": self.clean,
            "unicode_findings": [f.to_dict() for f in self.unicode_findings],
            "pii_findings": [
                {
                    "start": f.start,
                    "end": f.end,
                    "category": f.category,
                    "severity": f.severity,
                    "detector": f.detector,
                    "replacement": f.replacement,
                }
                for f in self.pii_findings
            ],
        }


def scan(text: str, options: ScanOptions | None = None) -> ScanResult:
    """Scan ``text`` for Unicode abuses (and optionally PII), returning findings
    plus a cleaned string. Does not modify the input."""
    opts = options or ScanOptions()
    cleaned, ufindings = unicode_scan.clean_text(text, opts.unicode)

    pii: list[Finding] = []
    if opts.pii:
        # Detect PII/secrets on the Unicode-cleaned text so offsets line up with
        # what a downstream consumer actually receives, then redact them too.
        pii = [
            f
            for f in detectors.detect(cleaned)
            if f.category in ("pii", "secret")
        ]
        if pii:
            cleaned = _apply_pii(cleaned, pii)

    return ScanResult(source=text, clean=cleaned, unicode_findings=ufindings, pii_findings=pii)


def clean(text: str, options: ScanOptions | None = None) -> str:
    """Return the cleaned text (convenience wrapper over :func:`scan`)."""
    return scan(text, options).clean


def _apply_pii(text: str, findings: list[Finding]) -> str:
    out: list[str] = []
    cursor = 0
    for f in sorted(findings, key=lambda x: x.start):
        if f.start < cursor:
            continue  # skip overlaps
        out.append(text[cursor : f.start])
        out.append(f.replacement)
        cursor = f.end
    out.append(text[cursor:])
    return "".join(out)
