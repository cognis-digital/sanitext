"""Demo: zero-width / invisible characters smuggled into text, stripped.

Zero-width spaces, joiners, and a BOM are used to hide watermarks or break up
tokens (e.g. to evade a naive keyword filter). sanitext removes them and shows
what was hidden.
"""

from sanitext import scan
from sanitext.report import render_scan

# "activate" with a zero-width space breaking it, a BOM prefix, and a ZWJ.
SMUGGLED = "﻿please acti​va‍te the account"


def main() -> int:
    print("== Zero-width smuggling ==")
    result = scan(SMUGGLED)
    print(render_scan(result))
    zw = [f for f in result.findings if f.category in ("zero_width", "invisible")]
    assert zw, "expected zero-width findings"
    assert result.clean == "please activate the account"
    assert result.dangerous
    print(f"\nOK: {len(zw)} invisible char(s) stripped; text now legible.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
