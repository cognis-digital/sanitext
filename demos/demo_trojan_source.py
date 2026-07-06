"""Demo: a Trojan-Source (CVE-2021-42574) bidi attack, detected and cleaned.

The snippet below embeds a RIGHT-TO-LEFT OVERRIDE and directional isolates so
that the *rendered* comment reads differently from the logical byte order a
compiler sees. sanitext flags every bidi control and strips them.
"""

from sanitext import scan
from sanitext.report import render_scan

# A classic Trojan-Source style line: the RLO + isolates reorder a comment.
MALICIOUS = 'if access_level != "user‮ ⁦// Check if admin⁩ ⁦" {'


def main() -> int:
    result = scan(MALICIOUS)
    print("== Trojan-Source bidi attack ==")
    print(render_scan(result))
    print()
    bidi_findings = [f for f in result.findings if f.category == "bidi"]
    assert bidi_findings, "expected bidi controls to be detected"
    assert result.dangerous
    # cleaned text carries no bidi controls
    from sanitext import bidi

    assert not bidi.contains_bidi(result.clean)
    print(f"OK: {len(bidi_findings)} bidi control(s) detected and stripped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
