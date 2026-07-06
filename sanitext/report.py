"""Scoring and change reports.

Two report families live here:

  * :func:`build` / :class:`Report` -- the legacy policy-acceptability score used
    by the optional provider-normalizer layer.
  * :func:`render_scan` -- the flagship human-readable before/after report for a
    Unicode-security :class:`~sanitext.core.ScanResult`, listing each finding's
    offset, code point, name, category, and action.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass

from .detectors import Finding
from .policies import Policy


@dataclass(frozen=True)
class Report:
    provider: str
    score: int
    acceptable: bool
    threshold: int
    blocked_by: list
    counts: dict
    findings: list

    def to_dict(self) -> dict:
        d = asdict(self)
        d["findings"] = [asdict(f) for f in self.findings]
        return d

    def summary(self) -> str:
        verdict = "ACCEPTABLE" if self.acceptable else "NOT ACCEPTABLE"
        lines = [f"[{self.provider}] {verdict}  score={self.score}/100 (threshold {self.threshold})"]
        if self.blocked_by:
            lines.append("  blocked by: " + ", ".join(sorted(set(self.blocked_by))))
        if self.counts:
            lines.append("  findings: " + ", ".join(f"{k}={v}" for k, v in sorted(self.counts.items())))
        else:
            lines.append("  findings: none")
        return "\n".join(lines)


def build(findings: list[Finding], policy: Policy) -> Report:
    counts = Counter(f.category for f in findings)
    penalty = sum(policy.weights.get(f.category, 5) for f in findings)
    score = max(0, 100 - penalty)
    blocked = sorted({f.category for f in findings if f.category in policy.blocking})
    acceptable = (not blocked) and score >= policy.threshold
    return Report(
        provider=policy.name,
        score=score,
        acceptable=acceptable,
        threshold=policy.threshold,
        blocked_by=blocked,
        counts=dict(counts),
        findings=list(findings),
    )


# --- Unicode-security scan report ------------------------------------------

def _visible(ch: str) -> str:
    """Render an invisible/control char as a placeholder so the table is legible."""
    cp = ord(ch)
    if cp < 0x20 or cp == 0x7F or (0x80 <= cp <= 0x9F):
        return f"\\x{cp:02x}"
    import unicodedata

    if unicodedata.category(ch) in ("Cf", "Cc") or ch.isspace():
        return "·"  # middle dot placeholder for otherwise-invisible glyphs
    return ch


def render_scan(result, *, color: bool = False) -> str:
    """Render a human-readable before/after report for a scan result.

    Lists each Unicode finding (offset, code point, name, category, action) and
    each PII/secret finding, then a verdict line suitable for a CI log.
    ``result`` is a :class:`sanitext.core.ScanResult`.
    """
    lines: list[str] = []
    uf = result.unicode_findings
    pf = result.pii_findings

    if not uf and not pf:
        lines.append("sanitext: no dangerous characters or PII found.")
        return "\n".join(lines)

    if uf:
        lines.append(f"Unicode-security findings ({len(uf)}):")
        lines.append(
            f"  {'off':>5}  {'codepoint':<9}  {'cat':<10}  {'gc':<3}  {'action':<10}  name"
        )
        for f in uf:
            lines.append(
                f"  {f.offset:>5}  {f.codepoint:<9}  {f.category:<10}  "
                f"{f.unicode_category:<3}  {f.action:<10}  {f.name}"
            )

    if pf:
        lines.append(f"PII / secret findings ({len(pf)}):")
        for f in pf:
            lines.append(
                f"  {f.start:>5}..{f.end:<5}  {f.category:<7}  {f.detector:<14}  -> {f.replacement}"
            )

    # Before/after preview (truncated).
    def _clip(s: str, n: int = 80) -> str:
        s = "".join(_visible(c) for c in s)
        return s if len(s) <= n else s[: n - 1] + "…"

    lines.append("Before/after:")
    lines.append(f"  before: {_clip(result.source)}")
    lines.append(f"  after : {_clip(result.clean)}")

    verdict = "DANGEROUS" if result.dangerous else "clean-ish"
    counts = ", ".join(f"{k}={v}" for k, v in sorted(result.counts().items()))
    lines.append(f"Verdict: {verdict}  ({counts})")
    return "\n".join(lines)
