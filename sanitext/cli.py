"""Command-line interface for sanitext."""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__, policies, rewriter
from .sanitizer import Lexicon, sanitize


def _read_input(args) -> str:
    if args.text is not None:
        return args.text
    if args.input in (None, "-"):
        return sys.stdin.read()
    with open(args.input, encoding="utf-8") as fh:
        return fh.read()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sanitext",
        description="Turn raw/uncensored text into provider-acceptable text "
                    "(strips profanity, slurs, PII, secrets, hostile tone).",
    )
    p.add_argument("input", nargs="?", help="input file path, or '-' for stdin (default)")
    p.add_argument("-t", "--text", help="inline text to process instead of a file")
    p.add_argument("-p", "--provider", default="generic", choices=sorted(policies.PROFILES),
                   help="destination policy profile (default: generic)")
    p.add_argument("-m", "--mode", default="rules", choices=["rules", "llm"],
                   help="rules = offline redaction (default); llm = model re-authoring")
    p.add_argument("--aggressive", action="store_true",
                   help="rules mode: drop sentences that still contain blocking findings")
    p.add_argument("--lexicon", help="path to a JSON lexicon to merge over the built-ins")

    g = p.add_argument_group("llm mode")
    g.add_argument("--backend", default="local", choices=["local", "anthropic", "openai"],
                   help="LLM backend (default: local Ollama-compatible server)")
    g.add_argument("--model", help="model id (backend-specific default if omitted)")
    g.add_argument("--base-url", help="local backend URL (default http://localhost:11434)")

    o = p.add_argument_group("output")
    o.add_argument("--json", action="store_true", help="emit {clean, report} as JSON")
    o.add_argument("--report", action="store_true", help="print the report to stderr")
    o.add_argument("--check", action="store_true",
                   help="don't rewrite; print the report and exit 1 if not acceptable")
    o.add_argument("-o", "--out", help="write cleaned text to this file instead of stdout")
    p.add_argument("-V", "--version", action="version", version=f"sanitext {__version__}")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    text = _read_input(args)

    lex = Lexicon.default()
    if args.lexicon:
        lex = lex.merged_with(args.lexicon)

    # Always run the rule pass: it produces the finding report and (in rules
    # mode) the cleaned text.
    result = sanitize(text, provider=args.provider, lexicon=lex, aggressive=args.aggressive)

    if args.check:
        print(result.report.summary(), file=sys.stderr)
        return 0 if result.report.acceptable else 1

    clean = result.clean
    if args.mode == "llm":
        try:
            clean = rewriter.rewrite(
                text,
                policy=policies.get(args.provider),
                backend=args.backend,
                model=args.model,
                base_url=args.base_url,
            )
        except Exception as e:  # surface backend errors without a traceback
            print(f"sanitext: llm backend error: {e}", file=sys.stderr)
            return 2

    if args.report:
        print(result.report.summary(), file=sys.stderr)

    if args.json:
        payload = result.to_dict()
        payload["clean"] = clean  # reflect llm output if used
        out = json.dumps(payload, indent=2, ensure_ascii=False)
    else:
        out = clean

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(out + ("\n" if not out.endswith("\n") else ""))
    else:
        print(out)
    return 0
