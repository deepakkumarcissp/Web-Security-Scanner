#!/usr/bin/env bash
# DKCISSP Web Security Scanner: automated end-to-end install check.
#
#   curl -fsSL https://raw.githubusercontent.com/deepakkumarcissp/Web-Security-Scanner/main/verify.sh | bash
#
# What it does, with no manual steps:
#   1. downloads the latest scanner from GitHub into a throwaway folder (your real install is never touched),
#   2. installs it with the real installer (private virtual environment, nothing system-wide),
#   3. starts it on a spare port with its own empty database (your scan history is never touched),
#   4. runs a real scan against a small built-in test website and checks the results,
#   5. stops everything, deletes the throwaway folder, and prints PASS or FAIL (exit code 0 or 1).
# It never installs scanning tools and never approves a package.
#
# Options: --branch NAME   --repo-url URL   --port N   --scan-timeout SECONDS   --report-dir DIR   --keep
# Environment: DKCISSP_REPO_URL, DKCISSP_BRANCH, DKCISSP_RAW_URL (where to fetch install.sh when piped)
set -uo pipefail

REPO_URL="${DKCISSP_REPO_URL:-https://github.com/deepakkumarcissp/Web-Security-Scanner.git}"
BRANCH="${DKCISSP_BRANCH:-main}"
RAW_URL="${DKCISSP_RAW_URL:-https://raw.githubusercontent.com/deepakkumarcissp/Web-Security-Scanner/main}"
PORT=""
SCAN_TIMEOUT=420
REPORT_DIR="${DKCISSP_VERIFY_REPORTS:-$HOME/dkcissp-verify-reports}"
KEEP=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --branch)       BRANCH="${2:?}"; shift 2 ;;
    --repo-url)     REPO_URL="${2:?}"; shift 2 ;;
    --port)         PORT="${2:?}"; shift 2 ;;
    --scan-timeout) SCAN_TIMEOUT="${2:?}"; shift 2 ;;
    --report-dir)   REPORT_DIR="${2:?}"; shift 2 ;;
    --keep)         KEEP=1; shift ;;
    -h|--help)      sed -n '2,16p' "$0" 2>/dev/null; exit 0 ;;
    *)              echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

WORK="$(mktemp -d "${TMPDIR:-/tmp}/dkcissp-verify.XXXXXX")"
SCANNER_PID=""
cleanup() {
  if [[ -n "$SCANNER_PID" ]]; then kill "$SCANNER_PID" 2>/dev/null; wait "$SCANNER_PID" 2>/dev/null; fi
  if (( KEEP )); then echo "Kept the test install in $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

echo "== DKCISSP install check =="
echo "   source : $REPO_URL ($BRANCH)"
echo "   system : $(uname -srm) | $(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-unknown}") | $(python3 -V 2>&1)"

# 1. The installer: use the one next to this script when run from a checkout, otherwise fetch it from GitHub.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"
if [[ -f "$HERE/install.sh" ]]; then INSTALLER="$HERE/install.sh"
else
  INSTALLER="$WORK/install.sh"
  curl -fsSL "$RAW_URL/install.sh" -o "$INSTALLER" || { echo "RESULT: FAIL (could not download the installer from $RAW_URL)"; exit 1; }
fi

# 2. Install into the throwaway folder.
echo "== Installing from GitHub into a throwaway folder =="
DKCISSP_REPO_URL="$REPO_URL" DKCISSP_BRANCH="$BRANCH" DKCISSP_BIN_DIR="$WORK/bin" \
  bash "$INSTALLER" --dir "$WORK/app" --no-start --no-browser || { echo "RESULT: FAIL (the installer failed)"; exit 1; }
COMMIT="$(git -C "$WORK/app" log -1 --format='%h %s' 2>/dev/null)"
echo "   installed: $COMMIT"

# 3. Start it on a spare port with its own empty database.
[[ -n "$PORT" ]] || PORT="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
echo "== Starting the scanner on 127.0.0.1:$PORT (private database) =="
DKCISSP_DB="$WORK/verify.sqlite3" DKCISSP_PORT="$PORT" "$WORK/app/run.sh" >"$WORK/scanner.log" 2>&1 &
SCANNER_PID=$!
for _ in $(seq 1 90); do
  curl -fsS -o /dev/null "http://127.0.0.1:$PORT/api/health" 2>/dev/null && break
  kill -0 "$SCANNER_PID" 2>/dev/null || break
  sleep 1
done
if ! curl -fsS -o /dev/null "http://127.0.0.1:$PORT/api/health" 2>/dev/null; then
  echo "RESULT: FAIL (the scanner did not start). Last log lines:"; tail -n 25 "$WORK/scanner.log"; exit 1
fi

# 4. Run the real checks.
mkdir -p "$REPORT_DIR"
REPORT="$REPORT_DIR/dkcissp-verify-$(date +%Y%m%d-%H%M%S).json"
echo "== Running the end-to-end checks =="
python3 "$WORK/app/scripts/selftest.py" --scanner "http://127.0.0.1:$PORT" --scan-timeout "$SCAN_TIMEOUT" --report "$REPORT"
STATUS=$?
echo "   tested commit: $COMMIT"
if (( STATUS != 0 )); then echo "   scanner log (last lines):"; tail -n 15 "$WORK/scanner.log" | sed 's/^/   | /'; fi
exit $STATUS
