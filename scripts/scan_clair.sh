#!/usr/bin/env bash
set -euo pipefail

SUBJECTS="${1:-subjects.yaml}"
OUT_DIR="reports/clair"
mkdir -p "$OUT_DIR"

CLAIR_HEALTH="http://localhost:6061/metrics"
if ! curl -fsSL "$CLAIR_HEALTH" >/dev/null; then
  echo "Clair not healthy. Start it: docker compose -f clair/docker-compose.yml up -d"
  exit 1
fi

# Push-side host view (where you pushed tars)
PUSH_REG="${PUSH_REGISTRY:-localhost:5001}"
# Pull-side view for Clair in its container
PULL_REG_FOR_CLAIR="${PULL_REGISTRY_FOR_CLAIR:-host.docker.internal:5001}"

# read subjects list
mapfile -t REFS < <(awk '/^subjects:/ {f=1; next} f && /^ *- / {sub(/^ *- */,""); print}' "$SUBJECTS" | sed '/^#/d;/^$/d')
echo "Found ${#REFS[@]} subjects."

for REF in "${REFS[@]}"; do
  ORIG="$REF"

  # Lock tag→digest for reproducibility if needed
  if [[ "$REF" != *@sha256:* ]]; then
    echo "Resolving tag to digest: $REF"
    docker pull "$REF" >/dev/null
    NAME="$(echo "$REF" | awk -F'[:@]' '{print $1}')"
    DIGEST="$(docker inspect --format='{{index .RepoDigests 0}}' "$REF" | awk -F'@' '{print $2}')"
    [[ -n "$DIGEST" ]] || { echo "Could not resolve digest for $REF"; exit 1; }
    REF="${NAME}@${DIGEST}"
  fi

  # Rewrite the host-exposed registry (PUSH_REG) to Clair’s viewpoint (PULL_REG_FOR_CLAIR)
  CLAIR_REF="$REF"
  if [[ "$REF" == "$PUSH_REG"* ]]; then
    CLAIR_REF="${REF/$PUSH_REG/$PULL_REG_FOR_CLAIR}"
  fi

# --- inside your for REF in ... loop ---

SAFE="$(echo "$ORIG" | sed -e 's|/|_|g' -e 's|:|_|g' -e 's|@|_|g')"
OUT="$OUT_DIR/${SAFE}.json"

echo "Clair scanning (as seen by Clair): $CLAIR_REF"
# IMPORTANT: do NOT pass --insecure-tls; clairctl doesn't support it.
# If Clair must pull from an HTTP registry, keep using the compose-attached registry service
# and the host.docker.internal mapping you already set in .env.
TMP="$(mktemp)"
if ! clairctl report --out json "$CLAIR_REF" > "$TMP" 2> "$TMP.err"; then
  echo "clairctl failed for $CLAIR_REF:"
  sed -n '1,60p' "$TMP.err"
  rm -f "$TMP" "$TMP.err"
  continue
fi

# Minimal validation: make sure output begins with '{' (JSON object)
if head -c 1 "$TMP" | grep -q '{'; then
  mv "$TMP" "$OUT"
  rm -f "$TMP.err"
  echo "→ $OUT"
else
  echo "Non-JSON output for $CLAIR_REF — not saving. First lines:"
  sed -n '1,20p' "$TMP"
  echo "(stderr)"
  sed -n '1,20p' "$TMP.err"
  rm -f "$TMP" "$TMP.err"
fi

echo "All Clair reports at $OUT_DIR"
