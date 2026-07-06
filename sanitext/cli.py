"""Command-line interface for sanitext.

Two primary subcommands center the Unicode-security engine:

    sanitext scan FILE     report findings; exit 1 if dangerous chars found (CI gate)
    sanitext clean FILE     emit cleaned text to stdout

A legacy top-level form (``sanitext FILE`` with no subcommand) runs the
provider-normalizer for backward compatibility.

Output is written as UTF-8 with a replacement fallback so it prints on Windows
cp1252 consoles without crashing (a known gotcha when a tool must emit the very
unicode it scans for).
"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__, policies
from .core import ScanOptions, scan
from .report import render_scan
from .sanitizer import Lexicon, sanitize
from .unicode_scan import UnicodeScanOptions


def _configure_stdio() -> None:
    """Make stdout/stderr emit UTF-8 with errors='replace' where supported.

    On Windows the default console encoding (cp1252) raises UnicodeEncodeError
    on many of the characters this tool reports. Reconfiguring to UTF-8 with a
    replacement fallback keeps output legible and crash-free everywhere.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass


def _read_input(path: str | None, text: str | None) -> str:
    if text is not None:
        return text
    if path in (None, "-"):
        # Read stdin as UTF-8 with a tolerant fallback; malformed bytes must not
        # crash a scanner whose whole job is malformed input.
        data = sys.stdin.buffer.read() if hasattr(sys.stdin, "buffer") else sys.stdin.read().encode()
        return data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _scan_options(args) -> ScanOptions:
    u = UnicodeScanOptions(
        bidi=not args.no_bidi,
        zero_width=not args.no_zero_width,
        invisible=not args.no_invisible,
        control=not args.no_control,
        homoglyph=not args.no_homoglyph,
        normalize_homoglyphs=not args.flag_only_homoglyphs,
    )
    return ScanOptions(unicode=u, pii=not args.no_pii)


def _add_scan_toggles(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("category toggles")
    g.add_argument("--no-bidi", action="store_true", help="do not scan/strip bidi controls")
    g.add_argument("--no-zero-width", action="store_true", help="do not scan/strip zero-width chars")
    g.add_argument("--no-invisible", action="store_true", help="do not scan/strip invisible/format chars")
    g.add_argument("--no-control", action="store_true", help="do not scan/strip control chars")
    g.add_argument("--no-homoglyph", action="store_true", help="do not scan homoglyphs/confusables")
    g.add_argument("--no-pii", action="store_true", help="do not scan/redact PII and secrets")
    g.add_argument("--flag-only-homoglyphs", action="store_true",
                   help="report homoglyphs but do not normalize them to ASCII")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sanitext",
        description="Detect and strip dangerous Unicode (bidi/Trojan-Source, "
                    "zero-width, control chars, homoglyphs) plus optional PII/secrets.",
    )
    p.add_argument("-V", "--version", action="version", version=f"sanitext {__version__}")
    sub = p.add_subparsers(dest="command")

    # scan
    sc = sub.add_parser("scan", help="report findings; exit 1 if dangerous chars found")
    sc.add_argument("input", nargs="?", help="input file, or '-'/omit for stdin")
    sc.add_argument("-t", "--text", help="inline text instead of a file")
    sc.add_argument("--json", action="store_true", help="emit findings as JSON")
    sc.add_argument("--sarif", action="store_true", help="emit findings as SARIF 2.1.0")
    sc.add_argument("--report", action="store_true", help="human before/after report (default if no format)")
    _add_scan_toggles(sc)

    # clean
    cl = sub.add_parser("clean", help="emit cleaned text (dangerous chars removed)")
    cl.add_argument("input", nargs="?", help="input file, or '-'/omit for stdin")
    cl.add_argument("-t", "--text", help="inline text instead of a file")
    cl.add_argument("--json", action="store_true", help="emit {clean, findings...} as JSON")
    cl.add_argument("--report", action="store_true", help="also print the report to stderr")
    cl.add_argument("-o", "--out", help="write cleaned text to this file instead of stdout")
    _add_scan_toggles(cl)

    # legacy provider-normalizer (backward compatible)
    lg = sub.add_parser("normalize", help="legacy provider-normalizer (profanity/tone/PII)")
    _add_legacy_args(lg)

    return p


def _add_legacy_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("input", nargs="?", help="input file path, or '-' for stdin")
    p.add_argument("-t", "--text", help="inline text to process instead of a file")
    p.add_argument("-p", "--provider", default="generic", choices=sorted(policies.PROFILES),
                   help="destination policy profile (default: generic)")
    p.add_argument("--aggressive", action="store_true",
                   help="drop sentences that still contain blocking findings")
    p.add_argument("--lexicon", help="path to a JSON lexicon to merge over the built-ins")
    p.add_argument("--json", action="store_true", help="emit {clean, report} as JSON")
    p.add_argument("--report", action="store_true", help="print the report to stderr")
    p.add_argument("--check", action="store_true", help="score only; exit 1 if not acceptable")
    p.add_argument("-o", "--out", help="write cleaned text to this file instead of stdout")


def _emit(text: str, out_path: str | None) -> None:
    if out_path:
        with open(out_path, "w", encoding="utf-8", errors="replace") as fh:
            fh.write(text + ("\n" if not text.endswith("\n") else ""))
    else:
        print(text)


def _cmd_scan(args) -> int:
    text = _read_input(args.input, args.text)
    result = scan(text, _scan_options(args))
    if args.json:
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    elif args.sarif:
        from .sarif import to_sarif

        uri = args.input if args.input and args.input != "-" else "input"
        print(json.dumps(to_sarif(result, artifact_uri=uri), indent=2, ensure_ascii=False))
    else:
        print(render_scan(result))
    return 1 if result.dangerous else 0


def _cmd_clean(args) -> int:
    text = _read_input(args.input, args.text)
    result = scan(text, _scan_options(args))
    if args.report:
        print(render_scan(result), file=sys.stderr)
    if args.json:
        _emit(json.dumps(result.to_dict(), indent=2, ensure_ascii=False), args.out)
    else:
        _emit(result.clean, args.out)
    return 0


def _cmd_normalize(args) -> int:
    text = _read_input(args.input, args.text)
    lex = Lexicon.default()
    if args.lexicon:
        lex = lex.merged_with(args.lexicon)
    result = sanitize(text, provider=args.provider, lexicon=lex, aggressive=args.aggressive)
    if args.check:
        print(result.report.summary(), file=sys.stderr)
        return 0 if result.report.acceptable else 1
    if args.report:
        print(result.report.summary(), file=sys.stderr)
    if args.json:
        _emit(json.dumps(result.to_dict(), indent=2, ensure_ascii=False), args.out)
    else:
        _emit(result.clean, args.out)
    return 0


def main(argv=None) -> int:
    _configure_stdio()
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()

    # Backward-compat: `sanitext FILE ...` with no subcommand -> normalize.
    known = {"scan", "clean", "normalize"}
    if argv and argv[0] not in known and not argv[0].startswith("-"):
        argv = ["normalize"] + argv
    elif argv and argv[0].startswith("-") and not any(a in known for a in argv):
        # bare flags like `-t "..."` -> legacy normalize for compatibility
        if argv[0] not in ("-V", "--version", "-h", "--help"):
            argv = ["normalize"] + argv

    args = parser.parse_args(argv)
    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "clean":
        return _cmd_clean(args)
    if args.command == "normalize":
        return _cmd_normalize(args)
    parser.print_help()
    return 0
