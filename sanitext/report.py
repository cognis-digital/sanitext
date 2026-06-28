"""Scoring and change reports."""

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
