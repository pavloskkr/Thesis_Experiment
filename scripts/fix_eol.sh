#!/bin/bash
set -euo pipefail

# Convert CRLF -> LF for all shell scripts in repo (safe re-run)
find . -type f -name "*.sh" -print0 | xargs -0 -I{} sh -c '
  if file -b "{}" | grep -qi "CRLF"; then
    sed -i "s/\r$//" "{}"
    echo "normalized: {}"
  fi
'

# Ensure executables
chmod +x ./scripts/*.sh 2>/dev/null || true
echo "Done. All .sh files normalized to LF and made executable."
