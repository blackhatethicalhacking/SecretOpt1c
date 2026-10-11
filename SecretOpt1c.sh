#!/bin/bash
# SecretOpt1c v2 — thin launcher (keeps the classic muscle-memory entrypoint)
# The engine (and its built-in rainbow banner + interactive menu) lives in
# secretopt1c.py. This wrapper just forwards all arguments to the Python core.
#
#   ./SecretOpt1c.sh                       # interactive menu
#   ./SecretOpt1c.sh -d example.com --validate --sources crawl,wayback -v
#   ./SecretOpt1c.sh --list-rules          # show the detection modules
#
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Pick a Python
PY="$(command -v python3 || command -v python)"
if [ -z "$PY" ]; then
  echo "[!] Python 3 is required. Install it and retry."
  exit 1
fi

exec "$PY" "$DIR/secretopt1c.py" "$@"
