#!/usr/bin/env bash
# sanitext installer (macOS / Linux / WSL).
# Editable-installs the package and, if ~/.local/bin is on PATH, drops the
# one-word launchers there.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"

PY="${PYTHON:-python3}"
if ! command -v "$PY" >/dev/null 2>&1; then
  PY=python
fi

echo "Installing sanitext (editable) with $PY ..."
"$PY" -m pip install -e .

# Optional PATH launchers.
target="${HOME}/.local/bin"
if [ -d "$target" ]; then
  cp -f bin/sanitext "$target/sanitext" 2>/dev/null || true
  cp -f bin/sanitext.cmd "$target/sanitext.cmd" 2>/dev/null || true
  chmod +x "$target/sanitext" 2>/dev/null || true
  echo "Launchers copied to $target"
fi

echo "Done. Try:  sanitext scan -t \$'x\\u202ey'"
