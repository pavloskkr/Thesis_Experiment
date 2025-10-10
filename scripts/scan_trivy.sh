#!/usr/bin/env bash
set -euo pipefail

SUBJ_FILE="${1:-subjects.yaml}"
DATE_TAG="$(date +%d-%m-%Y)"
REPORT_DIR="reports/trivy/$DATE_TAG"
mkdir -p "$REPORT_DIR"

LOCAL_CA="certs/ca.crt"         # optional CA for local TLS registry
DEFAULT_SCHEME="https"
IGNORE_UNFIXED="${IGNORE_UNFIXED:-false}"   # set true to hide unfixed CVEs

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
    -w /workspace)
  [[ -f "$LOCAL_CA" ]] && DOCKER_TRIVY+=(-v "$PWD/$LOCAL_CA:/usr/local/share/ca-certificates/local-registry-ca.crt:ro")
  DOCKER_TRIVY+=(aquasec/trivy:latest)
fi

# ---- helpers ----
safe_name() { echo "$1" | sed -e 's|/|_|g' -e 's|:|_|g' -e 's|@|_|g'; }

rewrite_for_container() {
  # Replace only host:port; preserve tag/digest suffix
  local ref="$1"
  if [[ "$RUN_NATIVE" -eq 0 ]]; then
    case "$ref" in
      localhost:*)     ref="host.docker.internal:${ref#localhost:}";;
      127.0.0.1:*)     ref="host.docker.internal:${ref#127.0.0.1:}";;
      registry:5000/*) ref="${ref/registry:5000/host.docker.internal:5001}";;
    esac
  fi
  echo "$ref"
}

choose_valid_tag() {
  # Only used for name:tag (not digests). Keeps your existing logic.
  local host_repo="$1"  # e.g. localhost:5001/istio/ratings-v-buggy
  local want_tag="$2"
  local host="${host_repo%%/*}"
  local repo="${host_repo#*/}"
  local url="${DEFAULT_SCHEME}://${host}/v2/${repo}/tags/list"

  local tags_json
  if ! tags_json="$(curl -fsS ${LOCAL_CA:+--cacert "$LOCAL_CA"} "$url" 2>/dev/null)"; then
    echo "$want_tag"; return 0
  fi

  local tags=()
  if command -v jq >/dev/null 2>&1; then
    mapfile -t tags < <(printf '%s\n' "$tags_json" | jq -r '.tags[]?' | sed '/^null$/d')
  else
    mapfile -t tags < <(printf '%s\n' "$tags_json" | tr -d ' \n' \
      | sed -n 's/.*"tags":\[\([^]]*\)\].*/\1/p' | tr ',' '\n' | sed -e 's/"//g' -e '/^$/d')
  fi

  [[ ${#tags[@]} -eq 0 ]] && { echo "$want_tag"; return 0; }
  for t in "${tags[@]}"; do [[ "$t" == "$want_tag" ]] && { echo "$want_tag"; return 0; }; done
  for t in "${tags[@]}"; do [[ "$t" == "latest" ]]   && { echo "latest"; return 0; }; done
  echo "${tags[0]}"
}

refresh_trivy_db() {
  # Try modern/portable DB update options; degrade gracefully.
  if [[ "$RUN_NATIVE" -eq 1 ]]; then
    if trivy db --help 2>/dev/null | grep -q -E '\bupdate\b'; then
      trivy db update
    else
      echo "WARN: Couldn't find 'trivy db update'; proceeding without explicit prefetch."
    fi
  else
    if "${DOCKER_TRIVY[@]}" db --help 2>/dev/null | grep -q -E '\bupdate\b'; then
      "${DOCKER_TRIVY[@]}" db update
    else
      echo "WARN: Container trivy lacks 'db update'; proceeding without explicit prefetch."
    fi
  fi
}

# ---- load subjects ----
mapfile -t REFS < <(awk '/^subjects:/ {f=1; next} f && /^ *- / {sub(/^ *- */,""); print}' "$SUBJ_FILE" \
                   | sed 's/\r$//' | sed '/^#/d;/^$/d')
echo "Found ${#REFS[@]} subjects."

# ---- refresh DB once ----
refresh_trivy_db

# ---- common flags ----
SCANNER_FLAGS=(--quiet --format json --scanners vuln)
[[ "$IGNORE_UNFIXED" == "true" ]] && SCANNER_FLAGS+=(--ignore-unfixed)

# ---- main loop ----
for ORIG in "${REFS[@]}"; do
  ORIG="$(echo "$ORIG" | sed 's/\r$//')"

  # Keep digest refs intact; only validate tag for name:tag refs
  TARGET_FOR_TRIVY="$ORIG"
  if [[ "$ORIG" != *@sha256:* ]]; then
    NAME="${ORIG%:*}"
    WANT_TAG="${ORIG##*:}"
    if [[ "$NAME" != "$WANT_TAG" ]]; then
      VALID_TAG="$(choose_valid_tag "$NAME" "$WANT_TAG")"
      [[ "$VALID_TAG" != "$WANT_TAG" ]] && echo "  ↺ tag '$WANT_TAG' not found for $NAME, using '$VALID_TAG' instead"
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
    trivy image "${SCANNER_FLAGS[@]}" "${INSECURE[@]}" --output "$OUT" "$TARGET_FOR_TRIVY"
  else
    "${DOCKER_TRIVY[@]}" image "${SCANNER_FLAGS[@]}" "${INSECURE[@]}" --output "$OUT" "$TARGET_FOR_TRIVY"
  fi

  echo "→ $OUT"
done

echo "All Trivy reports at $REPORT_DIR"
