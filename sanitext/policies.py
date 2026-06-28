"""Provider policy profiles.

A profile describes what a given destination (Claude, ChatGPT, a generic public
channel) considers acceptable, and how to weight each finding category when
scoring. Profiles are deliberately close to one another -- the major providers
share the same baseline (no slurs, no leaked secrets, no abuse) -- but the
weights and pass threshold can be tuned per destination.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Policy:
    name: str
    # Categories that make text unacceptable no matter the score.
    blocking: frozenset = field(default_factory=frozenset)
    # Penalty per finding category, used to compute a 0-100 acceptability score.
    weights: dict = field(default_factory=dict)
    # Minimum score (after penalties) to be considered acceptable.
    threshold: int = 80
    # Human-facing label for the rewrite prompt.
    description: str = ""


_BASE_WEIGHTS = {
    "secret": 100,
    "slur": 100,
    "pii": 20,
    "hostility": 15,
    "profanity": 8,
}

PROFILES: dict[str, Policy] = {
    "generic": Policy(
        name="generic",
        blocking=frozenset({"secret", "slur"}),
        weights=dict(_BASE_WEIGHTS),
        threshold=80,
        description="any public AI provider or shared channel",
    ),
    "claude": Policy(
        name="claude",
        blocking=frozenset({"secret", "slur"}),
        weights=dict(_BASE_WEIGHTS),
        threshold=80,
        description="Anthropic's Claude (claude.ai / API)",
    ),
    "openai": Policy(
        name="openai",
        blocking=frozenset({"secret", "slur"}),
        weights=dict(_BASE_WEIGHTS),
        threshold=80,
        description="OpenAI's ChatGPT / API",
    ),
}


def get(name: str) -> Policy:
    try:
        return PROFILES[name]
    except KeyError:
        raise ValueError(f"unknown provider profile {name!r}; choose from {sorted(PROFILES)}") from None
