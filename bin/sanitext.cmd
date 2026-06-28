@echo off
REM ============================================================
REM  sanitext - ONE-WORD launcher: turn raw/uncensored text into
REM  provider-acceptable text (Claude / ChatGPT / any channel).
REM  Strips profanity, slurs, PII, secrets, hostile tone.
REM
REM  Usage:
REM    sanitext file.txt                 clean a file (offline rules)
REM    type raw.txt | sanitext           clean from stdin
REM    cog4 cc "draft" | sanitext -p claude
REM    sanitext file.txt --check -p openai   score only; exit 1 if not OK
REM    sanitext file.txt --mode llm --backend local --model omnicoder
REM    sanitext file.txt --json          machine-readable {clean, report}
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
