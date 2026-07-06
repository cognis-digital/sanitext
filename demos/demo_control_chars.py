"""Demo: C0/C1 control characters detected and stripped.

Control characters (NUL, BEL, ESC, and the C1 range) can corrupt logs, hide
terminal-escape injection, or break downstream parsers. Tab/newline/CR are kept
as legitimate whitespace.
"""

from sanitext import scan
from sanitext.report import render_scan

# NUL, BEL, ESC embedded; tab and newline preserved.
DIRTY = "user\x00name\x07\tvalue\x1b[31mred\nnext line"


def main() -> int:
    print("== Control characters ==")
    result = scan(DIRTY)
    print(render_scan(result))
    controls = [f for f in result.findings if f.category == "control"]
    assert len(controls) == 3  # NUL, BEL, ESC
    assert "\t" in result.clean and "\n" in result.clean  # whitespace kept
    assert "\x00" not in result.clean
    print(f"\nOK: {len(controls)} control char(s) stripped; whitespace preserved.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
