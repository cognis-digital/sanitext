"""Demo: the human before/after report on a blob with every finding class."""

from sanitext import scan
from sanitext.report import render_scan

BLOB = (
    "﻿Review this‮ commit: paypаl.com login for b​ob@example.com; "
    "key AKIAFAKEEXAMPLE12345\x07 done"
)


def main() -> int:
    print("== Before/after report (all finding classes) ==")
    result = scan(BLOB)
    print(render_scan(result))
    counts = result.counts()
    # bidi, zero_width, invisible/control, homoglyph, pii, secret all present
    assert result.dangerous
    assert counts.get("bidi", 0) >= 1
    assert counts.get("homoglyph", 0) >= 1
    print("\nOK: mixed blob reported and cleaned.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
