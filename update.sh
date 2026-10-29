#!/usr/bin/env bash
# Update the DKCISSP Web Security Scanner to the latest version on GitHub.
# Your scan data (data.sqlite3) is not part of the repository and is never touched.
set -euo pipefail
cd "$(dirname "$0")"

if [[ ! -d .git ]]; then
  echo "This folder is not a git clone, so it cannot update itself."
  echo "Clone it fresh instead:  git clone https://github.com/deepakkumarcissp/Web-Security-Scanner.git"
  echo "Then copy your old data.sqlite3 into the new folder to keep your scan history."
  exit 1
fi

if ! git pull --ff-only origin main; then
  echo
  echo "Update stopped: this folder has local changes that conflict with the new version."
  echo "Run 'git status' to see them. Your data.sqlite3 is safe."
  exit 1
fi

if [[ -d .venv ]]; then
  source .venv/bin/activate
  python -m pip install -q -r requirements.txt
fi

echo
echo "Updated to: $(git log -1 --format='%h %s')"
echo "Restart the scanner to use it: stop the running one (Ctrl+C), then run ./run.sh"
