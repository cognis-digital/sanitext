"""Run every sanitext demo. Exits 0 iff all demos pass. Offline, deterministic.

Usage::

    python demos/run_all.py
"""

from __future__ import annotations

import importlib
import io
import sys
from contextlib import redirect_stdout
from pathlib import Path

# Ensure the repo root is importable when run directly.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

DEMOS = [
    ("demo_trojan_source", "main"),
    ("demo_homoglyph_domain", "main"),
    ("demo_zero_width_smuggling", "main"),
    ("demo_control_chars", "main"),
    ("demo_mixed_pii_unicode", "main"),
    ("demo_before_after_report", "main"),
    ("demo_sarif_export", "main"),
    ("demo_cli_gate", "main_demo"),
]


def _configure_stdout() -> None:
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if reconfigure is not None:
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            pass


def main() -> int:
    _configure_stdout()
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    failures: list[str] = []
    for mod_name, func_name in DEMOS:
        mod = importlib.import_module(mod_name)
        func = getattr(mod, func_name)
        buf = io.StringIO()
        try:
            with redirect_stdout(buf):
                rc = func()
            if rc != 0:
                failures.append(f"{mod_name}: returned {rc}")
                print(f"[FAIL] {mod_name} (exit {rc})")
            else:
                print(f"[ OK ] {mod_name}")
        except Exception as e:  # pragma: no cover - demo failure path
            failures.append(f"{mod_name}: {e!r}")
            print(f"[FAIL] {mod_name}: {e!r}")

    print()
    if failures:
        print(f"{len(failures)} demo(s) failed:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"All {len(DEMOS)} demos passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
