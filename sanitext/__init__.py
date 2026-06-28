"""sanitext -- turn raw/uncensored text into provider-acceptable text.

Takes raw model output (profanity, slurs, PII, secrets, hostile tone) and
produces clean, professional prose you can safely paste into Claude, ChatGPT,
or any public channel. Two engines:

    sanitize()  -- offline, deterministic rule-based redaction/substitution
    rewrite()   -- LLM re-authoring (local fleet / Anthropic / OpenAI)

This is a compliance normalizer, not a filter-evasion tool: the goal is to make
text genuinely acceptable, not to slip prohibited content past safety systems.
"""

from __future__ import annotations

from .policies import PROFILES, Policy, get as get_policy
from .report import Report
from .rewriter import rewrite
from .sanitizer import Lexicon, Result, sanitize

__version__ = "0.1.0"
__all__ = [
    "sanitize",
    "rewrite",
    "Lexicon",
    "Result",
    "Report",
    "Policy",
    "PROFILES",
    "get_policy",
    "__version__",
]
