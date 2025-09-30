#!/usr/bin/env bash
set -euo pipefail

SUBJ_FILE="${1:-subjects.yaml}"
DATE_TAG="$(date +%d-%m-%Y)"
REPORT_DIR="reports/trivy/$DATE_TAG"
mkdir -p "$REPORT_DIR"

LOCAL_CA="certs/ca.crt"   # CA for your local TLS registry
DEFAULT_SCHEME="https"

# ---- choose native vs dockerized Trivy ----
if command -v trivy >/dev/null 2>&1; then
  echo "Using native Trivy."
  RUN_NATIVE=1
else
  echo "Trivy not found; using Dockerized Trivy."
  RUN_NATIVE=0
fi

if [[ "$RUN_NATIVE" -eq 0 ]]; then
  DOCKER_TRIVY=(docker run --rm
    --add-host=host.docker.internal:host-gateway
    -e TRIVY_CACHE_DIR=/root/.cache/trivy
    -e SSL_CERT_DIR=/etc/ssl/certs:/usr/local/share/ca-certificates
    -v "$PWD:/workspace"
    -v "$HOME/.cache/trivy:/root/.cache/trivy"
    -v "$PWD/$LOCAL_CA:/usr/local/share/ca-certificates/local-registry-ca.crt:ro"
    -w /workspace
    aquasec/trivy:latest)
fi

# ---- helpers ----
safe_name() { echo "$1" | sed -e 's|/|_|g' -e 's|:|_|g' -e 's|@|_|g'; }

rewrite_for_container() {
  # Map host-visible ref to what the Trivy container can reach
  local ref="$1"
  if [[ "$RUN_NATIVE" -eq 0 ]]; then
    case "$ref" in
      localhost:*)               echo "host.docker.internal:${ref#localhost:}"; return;;
      127.0.0.1:*)               echo "host.docker.internal:${ref#127.0.0.1:}"; return;;
      registry:5000/*)           echo "${ref/registry:5000/host.docker.internal:5001}"; return;;
    esac
  fi
  echo "$ref"
}

# Query the registry and choose a valid tag:
# - If desired tag exists → keep it
# - Else prefer 'latest' if present
# - Else fall back to the first available tag
choose_valid_tag() {
  local host_repo="$1"   # e.g. localhost:5001/istio/ratings-v-buggy
  local want_tag="$2"

  local host="${host_repo%%/*}"
  local repo="${host_repo#*/}"
  local url="${DEFAULT_SCHEME}://${host}/v2/${repo}/tags/list"

  # fetch tags
  local tags_json
  if ! tags_json="$(curl -fsS --cacert "$LOCAL_CA" "$url" 2>/dev/null)"; then
    # if we cannot query tags, just return want_tag as-is
    echo "$want_tag"
    return 0
  fi

  # parse tags (jq if present, otherwise POSIX-ish parsing)
  local tags=()
  if command -v jq >/dev/null 2>&1; then
    mapfile -t tags < <(printf '%s\n' "$tags_json" | jq -r '.tags[]?' | sed '/^null$/d')
  else
    mapfile -t tags < <(printf '%s\n' "$tags_json" | tr -d ' \n' \
      | sed -n 's/.*"tags":\[\([^]]*\)\].*/\1/p' | tr ',' '\n' | sed -e 's/"//g' -e '/^$/d')
  fi

  # no tags?
  [[ ${#tags[@]} -eq 0 ]] && { echo "$want_tag"; return 0; }

  # desired present?
  local t
  for t in "${tags[@]}"; do
    [[ "$t" == "$want_tag" ]] && { echo "$want_tag"; return 0; }
  done

  # prefer 'latest'
  for t in "${tags[@]}"; do
    [[ "$t" == "latest" ]] && { echo "latest"; return 0; }
  done

  # otherwise first tag
  echo "${tags[0]}"
}

# ---- load subjects (strip CR to avoid \r issues) ----
mapfile -t REFS < <(awk '/^subjects:/ {f=1; next} f && /^ *- / {sub(/^ *- */,""); print}' "$SUBJ_FILE" \
                   | sed 's/\r$//' | sed '/^#/d;/^$/d')
echo "Found ${#REFS[@]} subjects."

# ---- main loop ----
for ORIG in "${REFS[@]}"; do
  ORIG="$(echo "$ORIG" | sed 's/\r$//')"   # hard trim CR

  # If a digest-locked ref is present, prefer scanning by *tag* for remote pulls.
  # Derive tag from the left side if available; otherwise default to :latest.
  TARGET_FOR_TRIVY="$ORIG"
  if [[ "$ORIG" == *@sha256:* ]]; then
    BASE_NO_DIG="${ORIG%@*}"      # host:port/repo[:tag]
    if [[ "$BASE_NO_DIG" == *:* ]]; then
      WANT_TAG="${BASE_NO_DIG##*:}"
      NAME="${BASE_NO_DIG%:*}"
    else
      WANT_TAG="latest"
      NAME="$BASE_NO_DIG"
    fi

    # Validate/adjust tag against registry (fixes things like ratings-v-buggy:1.20.3 → latest)
    VALID_TAG="$(choose_valid_tag "$NAME" "$WANT_TAG")"
    if [[ "$VALID_TAG" != "$WANT_TAG" ]]; then
      echo "  ↺ tag '$WANT_TAG' not found for $NAME, using '$VALID_TAG' instead"
    fi
    TARGET_FOR_TRIVY="${NAME}:${VALID_TAG}"
  else
    # ORIG is likely name:tag; still validate to avoid MANIFEST_UNKNOWN
    NAME="${ORIG%:*}"
    WANT_TAG="${ORIG##*:}"
    if [[ "$NAME" != "$WANT_TAG" ]]; then
      VALID_TAG="$(choose_valid_tag "$NAME" "$WANT_TAG")"
      if [[ "$VALID_TAG" != "$WANT_TAG" ]]; then
        echo "  ↺ tag '$WANT_TAG' not found for $NAME, using '$VALID_TAG' instead"
      fi
      TARGET_FOR_TRIVY="${NAME}:${VALID_TAG}"
    fi
  fi

  TARGET_FOR_TRIVY="$(rewrite_for_container "$TARGET_FOR_TRIVY")"

  INSECURE=()
  case "$TARGET_FOR_TRIVY" in
    host.docker.internal:5001/*|localhost:5001/*|127.0.0.1:5001/*) INSECURE+=(--insecure);;
  esac

  SAFE="$(safe_name "$ORIG")"
  OUT="$REPORT_DIR/${SAFE}.json"

  echo "Trivy scanning: $TARGET_FOR_TRIVY   (from $ORIG)"

  if [[ "$RUN_NATIVE" -eq 1 ]]; then
    trivy image --quiet --ignore-unfixed --skip-db-update --skip-java-db-update \
      "${INSECURE[@]}" --format json --output "$OUT" "$TARGET_FOR_TRIVY"
  else
    "${DOCKER_TRIVY[@]}" image --quiet --ignore-unfixed --skip-db-update --skip-java-db-update \
      "${INSECURE[@]}" --format json --output "$OUT" "$TARGET_FOR_TRIVY"
  fi

  echo "→ $OUT"
done

echo "All Trivy reports at $REPORT_DIR"
