#!/usr/bin/env bash
set -euo pipefail

SUBJECTS="${1:-subjects.yaml}"
DATE_TAG="$(date +%d-%m-%Y)"
OUT_DIR="reports/clair/$DATE_TAG"
mkdir -p "$OUT_DIR"

CLAIR_HEALTH="http://localhost:6061/metrics"
if ! curl -fsSL "$CLAIR_HEALTH" >/dev/null; then
  echo "Clair not healthy. Start it: docker compose -f clair/docker-compose.yml up -d"
  exit 1
fi

export SSL_CERT_FILE="$(pwd)/certs/ca-bundle.crt"

PUSH_REG="${PUSH_REGISTRY:-localhost:5001}"
PULL_REG_FOR_CLAIR="${PULL_REGISTRY_FOR_CLAIR:-registry:5000}"

mapfile -t REFS < <(awk '/^subjects:/ {f=1; next} f && /^ *- / {sub(/^ *- */,""); print}' "$SUBJECTS" | sed '/^#/d;/^$/d')
echo "Found ${#REFS[@]} subjects."

for REF in "${REFS[@]}"; do
  ORIG="$REF"
  if [[ "$REF" != *@sha256:* ]]; then
    echo "Resolving tag to digest: $REF"
    docker pull "$REF" >/dev/null
    NAME="$(echo "$REF" | awk -F'[:@]' '{print $1}')"
    DIGEST="$(docker inspect --format='{{index .RepoDigests 0}}' "$REF" | awk -F'@' '{print $2}')"
    [[ -n "$DIGEST" ]] || { echo "Could not resolve digest for $REF"; exit 1; }
    REF="${NAME}@${DIGEST}"
  fi

  CLAIR_REF="$REF"
  CLAIR_HOST="${PULL_REGISTRY_FOR_CLAIR:-host.docker.internal:5001}"
  case "$CLAIR_REF" in
    localhost:5001/*|127.0.0.1:5001/*|host.docker.internal:5001/*|registry:5000/*)
      CLAIR_REF="$(echo "$REF" \
        | sed -e "s#^localhost:5001/#$CLAIR_HOST/#" \
              -e "s#^127\.0\.0\.1:5001/#$CLAIR_HOST/#" \
              -e "s#^host\.docker\.internal:5001/#$CLAIR_HOST/#" \
              -e "s#^registry:5000/#$CLAIR_HOST/#")"
      ;;
  esac

  SAFE="$(echo "$ORIG" | sed -e 's|/|_|g' -e 's|:|_|g' -e 's|@|_|g')"
  OUT="$OUT_DIR/${SAFE}.json"

  echo "Clair scanning (as seen by Clair): $CLAIR_REF"
  TMP="$(mktemp)"
  if ! clairctl report --out json "$CLAIR_REF" > "$TMP" 2> "$TMP.err"; then
    echo "clairctl failed for $CLAIR_REF:"
    sed -n '1,80p' "$TMP.err" || true
    rm -f "$TMP" "$TMP.err"
    continue
  fi

  # Save only if it's JSON
  if head -c 1 "$TMP" | grep -q '{'; then
    mv "$TMP" "$OUT"
    rm -f "$TMP.err"
    echo "→ $OUT"
  else
    echo "Non-JSON output for $CLAIR_REF — not saving."
    sed -n '1,40p' "$TMP"
    echo "(stderr)"
    sed -n '1,40p' "$TMP.err"
    rm -f "$TMP" "$TMP.err"
  fi
done

echo "All Clair reports at $OUT_DIR"
