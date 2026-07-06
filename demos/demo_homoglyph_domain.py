"""Demo: a homoglyph-spoofed domain / identifier detected and normalized.

"раypal.com" looks identical to "paypal.com" but the first two letters are
Cyrillic (U+0440, U+0430). sanitext reports the confusable code points and
normalizes them to their ASCII skeleton (Unicode UTS #39).
"""

from sanitext import confusables, scan
from sanitext.report import render_scan

SPOOF = "раypal.com"  # Cyrillic р + а
LOOKALIKE_ID = "аdmin_usеr"  # Cyrillic а and е


def main() -> int:
    print("== Homoglyph-spoofed domain ==")
    result = scan(SPOOF)
    print(render_scan(result))
    homos = [f for f in result.findings if f.category == "homoglyph"]
    assert homos, "expected homoglyph findings"
    assert result.clean == "paypal.com"
    assert confusables.skeleton(SPOOF) == "paypal.com"
    print(f"\nOK: {len(homos)} confusable(s); skeleton -> {result.clean!r}")

    print("\n== Spoofed identifier ==")
    r2 = scan(LOOKALIKE_ID)
    print(render_scan(r2))
    assert r2.clean == "admin_user"
    print(f"\nOK: {LOOKALIKE_ID!r} normalizes to {r2.clean!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
