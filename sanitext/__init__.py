"""sanitext -- defensive Unicode-security text sanitizer.

Pasted, committed, or ingested text can carry invisible attacks that survive
human review:

  * **bidi / Trojan-Source controls** (CVE-2021-42574) that reorder how source
    or prose *renders* versus how it *executes*;
  * **zero-width & invisible** characters used to smuggle or watermark content;
  * **control characters** (C0/C1); and
  * **homoglyphs / confusables** (Unicode UTS #39) that spoof ASCII identifiers,
    domains, and package names.

sanitext detects, reports (with per-character offsets, code points, and Unicode
names), and strips/normalizes these -- with an optional PII/secret redaction
layer on top. Standard-library only core.

Primary API::

    from sanitext import scan, clean
    result = scan(text)          # ScanResult: .findings, .clean, .dangerous
    cleaned = clean(text)        # just the cleaned string

The legacy provider-normalizer API (``sanitize`` / optional LLM ``rewrite``)
remains available for tone/profanity cleanup, but the Unicode-security layer is
the headline product.
"""

from __future__ import annotations

from .core import ScanOptions, ScanResult, clean, scan
from .policies import PROFILES, Policy
from .policies import get as get_policy
from .report import Report, render_scan
from .sanitizer import Lexicon, Result, sanitize
from .unicode_scan import UFinding, UnicodeScanOptions

__version__ = "0.2.0"
__all__ = [
    # flagship Unicode-security API
    "scan",
    "clean",
    "ScanResult",
    "ScanOptions",
    "UFinding",
    "UnicodeScanOptions",
    "render_scan",
    # legacy provider-normalizer API
    "sanitize",
    "Lexicon",
    "Result",
    "Report",
    "Policy",
    "PROFILES",
    "get_policy",
    "__version__",
]


def __getattr__(name: str):
    # Lazily expose the optional LLM rewriter without importing it eagerly.
    if name == "rewrite":
        from .rewriter import rewrite

        return rewrite
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
