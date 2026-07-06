@echo off
REM ============================================================
REM  sanitext - ONE-WORD launcher: defensive Unicode-security
REM  text sanitizer. Detects/strips bidi (Trojan-Source), zero-width,
REM  control chars, and homoglyphs, plus optional PII/secret redaction.
REM
REM  Usage:
REM    sanitext scan file.txt            report; exit 1 if dangerous chars
REM    sanitext clean file.txt           emit cleaned text
REM    type raw.txt | sanitext scan -    scan from stdin
REM    sanitext scan file.txt --json     machine-readable findings
REM    sanitext scan file.txt --sarif    SARIF 2.1.0 for code scanning
REM    sanitext normalize file.txt       legacy profanity/tone/PII normalizer
REM
REM  Calls the editable-installed console script directly so it works
REM  from any CWD (incl. C:\Users\user). Lives on PATH at ~/.local/bin.
REM ============================================================
setlocal
set "EXE=C:\Users\user\AppData\Roaming\Python\Python314\Scripts\sanitext.exe"
if exist "%EXE%" (
  "%EXE%" %*
) else (
  REM Fallback: run the module with an explicit dir so the repo-root
  REM namespace collision at C:\Users\user can't shadow the package.
  C:\Python314\python.exe -c "import sys; sys.path.insert(0, r'C:\Users\user\sanitext'); from sanitext.cli import main; sys.exit(main())" %*
)
endlocal
