#!/usr/bin/env bash
set -euo pipefail

# --- make cron environment sane ---
export SHELL="/bin/bash"
export HOME="${HOME:-/home/$USER}"
# Ensure typical interactive paths + Go bin where clairctl is often installed
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${HOME}/.local/bin:${HOME}/bin:${HOME}/go/bin:${PATH}"

# --- resolve repo root & enter it (works from cron) ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

# --- config ---
COMPOSE_FILE="clair/docker-compose.yml"
CLAIR_HEALTH_URL="http://localhost:6061/metrics"
SUBJECTS_FILE="${1:-subjects.yaml}"
TODAY="$(date +%d-%m-%Y)"
OUT_DIR="out"

# --- ensure Clair stack is running ---
echo "# Ensuring Clair stack is up..."
docker compose -f "${COMPOSE_FILE}" up -d >/dev/null

# --- wait for Clair health endpoint ---
echo "# Waiting for Clair to become healthy at ${CLAIR_HEALTH_URL} ..."
ATTEMPTS=60   # ~60 * 2s = 120s max
i=0
until curl -fsS "${CLAIR_HEALTH_URL}" >/dev/null 2>&1; do
  i=$((i+1))
  if [ "${i}" -ge "${ATTEMPTS}" ]; then
    echo "ERROR: Clair health endpoint not ready after ~120s. Check 'docker compose -f ${COMPOSE_FILE} logs -f clair'." >&2
    exit 1
  fi
  sleep 2
done
echo "# Clair is healthy."

# --- scans (each script creates its own dated reports/<tool>/<dd-mm-yyyy>/...) ---
./scripts/scan_trivy.sh "${SUBJECTS_FILE}"
./scripts/scan_clair.sh "${SUBJECTS_FILE}"

# --- aggregate into out/<date> ---
python3 -m scripts.aggregate reports "${OUT_DIR}"
echo "# Aggregates written to ${OUT_DIR}"
