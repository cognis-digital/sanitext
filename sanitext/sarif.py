"""SARIF 2.1.0 export for sanitext findings.

SARIF (Static Analysis Results Interchange Format, OASIS standard, schema
version 2.1.0) is understood by GitHub code scanning, VS Code, and most CI
dashboards. Emitting SARIF lets sanitext act as a code-scanning tool: run it in
CI and surface bidi/Trojan-Source, invisible-character, and homoglyph findings
as annotations on the offending file and character offset.

Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

from .core import ScanResult
from .unicode_scan import UFinding

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)

# Map sanitext categories to SARIF rules.
_RULES = {
    "bidi": {
        "id": "sanitext/bidi-control",
        "name": "BidiControlCharacter",
        "shortDescription": "Bidirectional control character (Trojan-Source)",
        "helpUri": "https://trojansource.codes/",
        "level": "error",
    },
    "zero_width": {
        "id": "sanitext/zero-width",
        "name": "ZeroWidthCharacter",
        "shortDescription": "Zero-width / invisible formatting character",
        "helpUri": "https://www.unicode.org/reports/tr39/",
        "level": "error",
    },
    "invisible": {
        "id": "sanitext/invisible",
        "name": "InvisibleCharacter",
        "shortDescription": "Invisible format / variation-selector character",
        "helpUri": "https://www.unicode.org/reports/tr39/",
        "level": "error",
    },
    "control": {
        "id": "sanitext/control-char",
        "name": "ControlCharacter",
        "shortDescription": "C0/C1 control character",
        "helpUri": "https://www.unicode.org/reports/tr39/",
        "level": "warning",
    },
    "homoglyph": {
        "id": "sanitext/homoglyph",
        "name": "Homoglyph",
        "shortDescription": "Homoglyph confusable with ASCII (UTS #39)",
        "helpUri": "https://www.unicode.org/reports/tr39/",
        "level": "warning",
    },
}

_LEVEL_BY_SEVERITY = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def _rule_index(order: list[str], category: str) -> int:
    if category not in order:
        order.append(category)
    return order.index(category)


def to_sarif(result: ScanResult, *, artifact_uri: str = "input.txt") -> dict:
    """Build a SARIF 2.1.0 log object for a :class:`ScanResult`.

    ``artifact_uri`` names the scanned artifact in the report locations.
    Offsets are emitted both as a region (startColumn on line 1, 1-based) and,
    for multi-line inputs, translated to (line, column) so viewers annotate the
    right spot.
    """
    order: list[str] = []
    results = []
    line_starts = _line_offsets(result.source)

    for f in result.unicode_findings:
        idx = _rule_index(order, f.category)
        line, col = _to_line_col(f.offset, line_starts)
        rule = _RULES[f.category]
        results.append(
            {
                "ruleId": rule["id"],
                "ruleIndex": idx,
                "level": _LEVEL_BY_SEVERITY.get(f.severity, rule["level"]),
                "message": {
                    "text": (
                        f"{f.name} ({f.codepoint}, category {f.unicode_category}) "
                        f"at offset {f.offset}: {f.detail}. Action: {f.action}."
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": artifact_uri},
                            "region": {
                                "startLine": line,
                                "startColumn": col,
                                "endColumn": col + 1,
                                "charOffset": f.offset,
                                "charLength": 1,
                            },
                        }
                    }
                ],
                "properties": {
                    "codepoint": f.codepoint,
                    "unicodeCategory": f.unicode_category,
                    "severity": f.severity,
                    "action": f.action,
                },
            }
        )

    rules = [
        {
            "id": _RULES[cat]["id"],
            "name": _RULES[cat]["name"],
            "shortDescription": {"text": _RULES[cat]["shortDescription"]},
            "helpUri": _RULES[cat]["helpUri"],
            "defaultConfiguration": {"level": _RULES[cat]["level"]},
        }
        for cat in order
    ]

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "sanitext",
                        "informationUri": "https://github.com/cognis-digital/sanitext",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def _line_offsets(text: str) -> list[int]:
    """Character offset at which each line starts (index 0 == line 1)."""
    starts = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            starts.append(i + 1)
    return starts


def _to_line_col(offset: int, line_starts: list[int]) -> tuple[int, int]:
    """Translate a 0-based char offset to 1-based (line, column)."""
    line = 1
    for i, start in enumerate(line_starts):
        if start <= offset:
            line = i + 1
        else:
            break
    col = offset - line_starts[line - 1] + 1
    return line, col
