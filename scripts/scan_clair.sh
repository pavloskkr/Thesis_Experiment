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

# host registry (where we pushed), as seen from host:
PUSH_REG="${PUSH_REGISTRY:-localhost:5001}"
# same registry as seen FROM Clair container (compose service name + internal port)
PULL_REG_FOR_CLAIR="${PULL_REGISTRY_FOR_CLAIR:-registry:5000}"

# Read refs
mapfile -t REFS < <(awk '/^subjects:/ {flag=1; next} flag && /^ *- / {gsub("^ *- *",""); print}' "$SUBJECTS" | sed '/^#/d;/^$/d')

echo "Found ${#REFS[@]} subjects."
for REF in "${REFS[@]}"; do
  ORIG="$REF"

  # If it's a tag (no @sha256), lock it to a digest for reproducibility.
  if [[ "$REF" != *@sha256:* ]]; then
    echo "Resolving tag to digest: $REF"
    docker pull "$REF" >/dev/null
    NAME="$(echo "$REF" | awk -F'[:@]' '{print $1}')"
    DIGEST="$(docker inspect --format='{{index .RepoDigests 0}}' "$REF" | awk -F'@' '{print $2}')"
    if [ -z "$DIGEST" ]; then
      echo "Could not resolve digest for $REF"; exit 1
    fi
    REF="${NAME}@${DIGEST}"
  fi

  # If ref points to host-exposed registry, rewrite for Clair's viewpoint.
  CLAIR_REF="$REF"
  if [[ "$REF" == "$PUSH_REG"* ]]; then
    CLAIR_REF="${REF/$PUSH_REG/$PULL_REG_FOR_CLAIR}"
  fi

  SAFE="$(echo "$ORIG" | sed -e 's|/|_|g' -e 's|:|_|g' -e 's|@|_|g')"
  OUT="$OUT_DIR/${SAFE}.json"

  echo "Clair scanning (as seen by Clair): $CLAIR_REF"
  # Don't pass --host; v4 clairctl talks to localhost:6060 by default
  clairctl report --out json "$CLAIR_REF" > "$OUT"
  echo "→ $OUT"
done

echo "All Clair reports at $OUT_DIR"
