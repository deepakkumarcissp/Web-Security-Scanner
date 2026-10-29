#!/usr/bin/env bash
# DKCISSP Web Security Scanner: one-command installer for Kali Linux and other Debian-based systems.
#
#   curl -fsSL https://raw.githubusercontent.com/deepakkumarcissp/Web-Security-Scanner/main/install.sh | bash
#
# It downloads the scanner from GitHub, installs its Python packages in a private virtual environment,
# creates a `dkcissp-scanner` command, starts the scanner and opens the dashboard.
# It does NOT install the scanning tools (Nuclei, Nikto, ZAP, ...). The scanner asks you, one tool at a time,
# on its Approvals page, the first time a scan needs one.
#
# Options (put them after `bash -s --`):  --dir PATH  --branch NAME  --port N  --no-start  --no-browser
# Environment: DKCISSP_HOME, DKCISSP_BRANCH, DKCISSP_PORT, DKCISSP_REPO_URL
set -euo pipefail

REPO_URL="${DKCISSP_REPO_URL:-https://github.com/deepakkumarcissp/Web-Security-Scanner.git}"
BRANCH="${DKCISSP_BRANCH:-main}"
DIR="${DKCISSP_HOME:-$HOME/DKCISSP-Web-Security-Scanner}"
PORT="${DKCISSP_PORT:-1005}"
START=1
BROWSER=1

if [[ -t 1 ]]; then B=$'\033[1m'; G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; N=$'\033[0m'; else B=""; G=""; Y=""; R=""; N=""; fi
step() { echo "${B}==>${N} $*"; }
ok()   { echo "${G} ok${N} $*"; }
warn() { echo "${Y}warn${N} $*"; }
die()  { echo "${R}error${N} $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir)        DIR="${2:?--dir needs a path}"; shift 2 ;;
    --branch)     BRANCH="${2:?--branch needs a name}"; shift 2 ;;
    --port)       PORT="${2:?--port needs a number}"; shift 2 ;;
    --no-start)   START=0; shift ;;
    --no-browser) BROWSER=0; shift ;;
    -h|--help)    cat <<'USAGE'
DKCISSP Web Security Scanner installer
  curl -fsSL https://raw.githubusercontent.com/deepakkumarcissp/Web-Security-Scanner/main/install.sh | bash
Options (after "bash -s --"):
  --dir PATH     install folder (default: ~/DKCISSP-Web-Security-Scanner)
  --branch NAME  branch to install (default: main)
  --port N       port to run on (default: 1005)
  --no-start     install only; do not start the scanner
  --no-browser   do not open the dashboard automatically
USAGE
                  exit 0 ;;
    *)            die "Unknown option: $1 (try --help)" ;;
  esac
done
[[ "$PORT" =~ ^[0-9]+$ ]] && (( PORT >= 1 && PORT <= 65535 )) || die "--port must be a number between 1 and 65535."

echo "${B}DKCISSP Web Security Scanner installer${N}"
[[ "$(uname -s)" == "Linux" ]] || die "This installer supports Linux (Kali or another Debian-based system)."
if [[ ${EUID:-$(id -u)} -eq 0 ]]; then warn "Running as root. A normal user account is recommended; the scanner is installed for the current user only."; fi

# 1. Prerequisites: git, curl, python3 (3.9+) with venv support. Only missing ones are installed, with apt.
step "Checking prerequisites"
need=()
command -v git     >/dev/null 2>&1 || need+=(git)
command -v curl    >/dev/null 2>&1 || need+=(curl)
command -v python3 >/dev/null 2>&1 || need+=(python3)
if command -v python3 >/dev/null 2>&1; then
  python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' || die "Python 3.9 or newer is required (found $(python3 -V 2>&1))."
  python3 -c 'import venv, ensurepip' >/dev/null 2>&1 || need+=(python3-venv)
fi
if (( ${#need[@]} )); then
  command -v apt-get >/dev/null 2>&1 || die "Missing: ${need[*]}. Install them with your package manager, then run this installer again."
  SUDO=""; [[ ${EUID:-$(id -u)} -eq 0 ]] || SUDO="sudo"
  [[ -z "$SUDO" ]] || command -v sudo >/dev/null 2>&1 || die "Missing: ${need[*]}, and sudo is not available. Install them as root, then run this installer again."
  warn "Installing missing prerequisites with apt: ${need[*]} (you may be asked for your password)"
  $SUDO apt-get update -qq
  $SUDO apt-get install -y "${need[@]}"
fi
ok "git, curl and python3 $(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])') with venv are ready"

# 2. Download (or update) the scanner from GitHub.
step "Getting the scanner from GitHub into $DIR"
if [[ -d "$DIR/.git" ]]; then
  git -C "$DIR" pull --ff-only origin "$BRANCH" >/dev/null 2>&1 \
    || die "Could not update the existing copy in $DIR (it has local changes, or GitHub is unreachable). Your data is untouched. Run 'git -C \"$DIR\" status' to look."
  ok "Existing installation updated to $(git -C "$DIR" log -1 --format='%h %s')"
elif [[ -e "$DIR" && -n "$(ls -A "$DIR" 2>/dev/null)" ]]; then
  die "$DIR already exists and is not a scanner clone, so it was left alone. Choose another folder with --dir PATH."
else
  git clone --quiet --branch "$BRANCH" "$REPO_URL" "$DIR" || die "Could not download $REPO_URL (branch $BRANCH). Check your internet connection."
  ok "Downloaded $(git -C "$DIR" log -1 --format='%h %s')"
fi
cd "$DIR"

# 3. Private Python environment and packages.
step "Installing Python packages (private virtual environment in $DIR/.venv)"
[[ -d .venv ]] || python3 -m venv .venv
.venv/bin/python -m pip install -q --upgrade pip >/dev/null 2>&1 || true
.venv/bin/python -m pip install -q -r requirements.txt || die "Installing the Python packages failed. Check your internet connection and run the installer again."
DKCISSP_DB="$(mktemp -u)" .venv/bin/python -c "import app" >/dev/null 2>&1 || die "The scanner downloaded but did not load. Please report this at https://github.com/deepakkumarcissp/Web-Security-Scanner/issues"
ok "Packages installed and the scanner loads"

# 4. A short command to start and update it.
step "Creating the dkcissp-scanner command"
BIN="$HOME/.local/bin"; mkdir -p "$BIN"
cat > "$BIN/dkcissp-scanner" <<LAUNCHER
#!/usr/bin/env bash
# DKCISSP Web Security Scanner launcher.   dkcissp-scanner [start|update]
DIR="$DIR"
case "\${1:-start}" in
  start)  shift || true; exec "\$DIR/run.sh" "\$@" ;;
  update) exec "\$DIR/update.sh" ;;
  *)      echo "Usage: dkcissp-scanner [start|update]"; exit 2 ;;
esac
LAUNCHER
chmod +x "$BIN/dkcissp-scanner"
case ":$PATH:" in *":$BIN:"*) ok "Run it any time with: dkcissp-scanner" ;;
  *) ok "Created $BIN/dkcissp-scanner"; warn "$BIN is not on your PATH yet. Open a new terminal, or run: export PATH=\"\$HOME/.local/bin:\$PATH\"" ;; esac

echo
echo "${G}${B}Installed.${N}  Folder: $DIR"
echo "  Start:   dkcissp-scanner          (or: $DIR/run.sh)"
echo "  Update:  dkcissp-scanner update   (your scan history is never touched)"
echo "  Scanning tools are installed only when you approve them on the Approvals page."
echo

# 5. Start it, and open the dashboard once it answers.
if (( START )); then
  export DKCISSP_PORT="$PORT"
  if (( BROWSER )) && command -v xdg-open >/dev/null 2>&1 && [[ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]]; then
    ( for _ in $(seq 1 40); do
        if curl -fsS -o /dev/null "http://127.0.0.1:$PORT/api/health" 2>/dev/null; then xdg-open "http://127.0.0.1:$PORT" >/dev/null 2>&1 || true; break; fi
        sleep 0.5
      done ) &
  fi
  step "Starting the scanner at http://127.0.0.1:$PORT  (press Ctrl+C to stop it)"
  exec "$DIR/run.sh"
fi
echo "Not started (--no-start). Start it with: dkcissp-scanner"
