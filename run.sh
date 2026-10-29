#!/usr/bin/env bash
# Start the DKCISSP Web Security Scanner on 127.0.0.1 (default port 1005; change with DKCISSP_PORT).
set -euo pipefail
cd "$(dirname "$0")"
PORT="${DKCISSP_PORT:-1005}"

if [[ ! -d .venv ]]; then python3 -m venv .venv; fi
source .venv/bin/activate
python -m pip install -q -r requirements.txt

# Refuse to start on top of something that is already listening (for example another scanner instance).
if python - "$PORT" <<'PY'
import socket, sys
s = socket.socket()
try:
    s.bind(("127.0.0.1", int(sys.argv[1])))
except OSError:
    sys.exit(1)
PY
then :; else
  echo "Port $PORT is already in use. Another scanner may be running, or something else owns the port."
  echo "Use another port with:  DKCISSP_PORT=1015 ./run.sh"
  exit 1
fi

echo "DKCISSP Web Security Scanner: http://127.0.0.1:$PORT   (press Ctrl+C to stop)"
exec uvicorn app:app --host 127.0.0.1 --port "$PORT"
