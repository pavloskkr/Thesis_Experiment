#!/bin/bash
set -euo pipefail

# cron-safe PATH
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${HOME:-}/.local/bin:${HOME:-}/bin:${HOME:-}/go/bin:${PATH}"

SUBJECTS="${1:-subjects.yaml}"
TODAY="$(date +%d-%m-%Y)"
OUT_DIR="reports/clair/${TODAY}"
mkdir -p "$OUT_DIR"

CLAIR_HEALTH="http://localhost:6061/metrics"
if ! curl -fsSL "$CLAIR_HEALTH" >/dev/null 2>&1; then
  echo "Clair not healthy. Start it: docker compose up -d"
  exit 1
fi

# Minimal Docker config (avoid credential helpers popups)
DOCKER_CFG_DIR="$(mktemp -d)"
trap 'rm -rf "$DOCKER_CFG_DIR"' EXIT
printf '%s\n' '{"auths":{},"credHelpers":{}}' > "$DOCKER_CFG_DIR/config.json"
export DOCKER_CONFIG="$DOCKER_CFG_DIR"

# ggcr flags so clairctl can talk to local TLS with self-signed
export GGCR_ALLOW_HTTP=1
export GGCR_INSECURE_SKIP_VERIFY=1

# Optional: custom CA bundle for clairctl (if you created one)
[ -f "$(pwd)/certs/ca-bundle.crt" ] && export SSL_CERT_FILE="$(pwd)/certs/ca-bundle.crt"

DEFAULT_SCHEME="https"
LOCAL_CA="certs/ca.crt"

map_for_clair_view() {
  local ref="$1"
  case "$ref" in
    localhost:5001/*)             echo "${ref/localhost:5001/host.docker.internal:5001}";;
    127.0.0.1:5001/*)             echo "${ref/127.0.0.1:5001/host.docker.internal:5001}";;
    registry:5000/*)              echo "${ref/registry:5000/host.docker.internal:5001}";;
    host.docker.internal:5001/*)  echo "$ref";;
    *)                            echo "$ref";;
  esac
}

# Query registry to make sure the tag exists; if not, pick a valid one (latest or first)
choose_valid_tag() {
  local host_repo="$1"   # e.g. localhost:5001/library/alpine
  local want_tag="$2"
  local host="${host_repo%%/*}"
  local repo="${host_repo#*/}"
  local url="${DEFAULT_SCHEME}://${host}/v2/${repo}/tags/list"

  local tags_json
  if ! tags_json="$(curl -fsS --cacert "$LOCAL_CA" "$url" 2>/dev/null)"; then
    echo "$want_tag"; return 0
  fi

  local tags=()
  if command -v jq >/dev/null 2>&1; then
    mapfile -t tags < <(printf '%s\n' "$tags_json" | jq -r '.tags[]?' | sed '/^null$/d')
  else
    mapfile -t tags < <(printf '%s\n' "$tags_json" | tr -d '\n ' \
      | sed -n 's/.*"tags":\[\([^]]*\)\].*/\1/p' | tr ',' '\n' | sed -e 's/"//g' -e '/^$/d')
  fi
  [[ ${#tags[@]} -eq 0 ]] && { echo "$want_tag"; return 0; }

  local t
  for t in "${tags[@]}"; do
    [[ "$t" == "$want_tag" ]] && { echo "$want_tag"; return 0; }
  done
  for t in "${tags[@]}"; do
    [[ "$t" == "latest" ]] && { echo "latest"; return 0; }
  done
  echo "${tags[0]}"
}

# docker pull <name:tag> then output NAME@sha256:... (single digest)
lock_to_digest() {
  local ref="$1"             # name:tag
  docker pull "$ref" >/dev/null
  local name="${ref%:*}"
  local dig
  dig="$(docker inspect --format='{{index .RepoDigests 0}}' "$ref" 2>/dev/null | awk -F'@' '{print $2}')"
  if [[ -z "${dig:-}" ]]; then
    echo "ERR: could not resolve digest for $ref" >&2
    return 1
  fi
  echo "${name}@${dig}"
}

# If manifest list, choose linux/amd64 child digest (best-effort)
child_amd64_from_index() {
  local ref="$1"
  local js; js="$(docker manifest inspect "$ref" 2>/dev/null || true)"
  [[ -z "$js" ]] && { echo "$ref"; return 0; }

  local mt
  mt="$(printf '%s' "$js" | tr -d '\n' | sed -n 's/.*"mediaType"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"

  case "$mt" in
    application/vnd.docker.distribution.manifest.list.v2+json|application/vnd.oci.image.index.v1+json)
      local child
      child="$(printf '%s' "$js" \
        | awk 'BEGIN{RS="\\{";FS="\\n"} /"platform"/ && /"os"[[:space:]]*:[[:space:]]*"linux"/ && /"architecture"[[:space:]]*:[[:space:]]*"amd64"/ {print "{"$0}' \
        | sed -n 's/.*"digest"[[:space:]]*:[[:space:]]*"\(sha256:[^"]*\)".*/\1/p' \
        | head -n1)"
      if [[ -n "$child" ]]; then
        echo "${ref%@*}@${child}"
        return 0
      fi
      ;;
  esac

  echo "$ref"
}

safe_name() { echo "$1" | sed -e 's|/|_|g' -e 's|:|_|g' -e 's|@|_|g'; }

# ---- load subjects (strip CRs) ----
mapfile -t REFS < <(awk '/^subjects:/ {f=1; next} f && /^ *- / {sub(/^ *- */,""); print}' "$SUBJECTS" \
                   | sed 's/\r$//' | sed '/^#/d;/^$/d')
echo "Found ${#REFS[@]} subjects."

for ORIG in "${REFS[@]}"; do
  ORIG="$(echo "$ORIG" | sed 's/\r$//')"

  # Derive NAME and TAG from original ref; if missing tag, use 'latest'
  if [[ "$ORIG" == *@sha256:* ]]; then
    BASE_NO_DIG="${ORIG%@*}"                 # strip @sha256
  else
    BASE_NO_DIG="$ORIG"
  fi

  if [[ "$BASE_NO_DIG" == *:* ]]; then
    ORIG_TAG="${BASE_NO_DIG##*:}"
    NAME_ONLY="${BASE_NO_DIG%:*}"
  else
    ORIG_TAG="latest"
    NAME_ONLY="$BASE_NO_DIG"
  fi

  # Validate tag against registry (fixes "latest" not present)
  VALID_TAG="$(choose_valid_tag "$NAME_ONLY" "$ORIG_TAG")"
  [[ "$VALID_TAG" != "$ORIG_TAG" ]] && echo "  ↺ tag '$ORIG_TAG' not found for $NAME_ONLY, using '$VALID_TAG' instead"
  TAG_REF="${NAME_ONLY}:${VALID_TAG}"

  # Lock to digest for stable Clair input
  echo "Resolving tag to digest: $TAG_REF"
  if ! REF="$(lock_to_digest "$TAG_REF")"; then
    echo "  ! skip $ORIG (digest resolution failed)"
    continue
  fi

  # If multi-arch index, pick linux/amd64 child
  AMD64_REF="$(child_amd64_from_index "$REF")"
  [[ "$AMD64_REF" != "$REF" ]] && { echo "  ↳ manifest list detected; using linux/amd64: ${AMD64_REF#*@}"; REF="$AMD64_REF"; }

  # Map both digest and tag refs to Clair’s viewpoint
  CLAIR_REF="$(map_for_clair_view "$REF")"
  CLAIR_TAG_REF="$(map_for_clair_view "$TAG_REF")"

  SAFE="$(safe_name "$ORIG")"
  OUT="${OUT_DIR}/${SAFE}.json"
  TMP="$(mktemp)"
  ERR="$(mktemp)"

  echo "Clair scanning (as seen by Clair): $CLAIR_REF"
  if timeout 90s clairctl report --out json "$CLAIR_REF" >"$TMP" 2>"$ERR"; then
    :
  else
    if grep -q 'MANIFEST_UNKNOWN' "$ERR"; then
      echo "  ↺ digest not resolvable; retrying by tag: $CLAIR_TAG_REF"
      : >"$TMP"; : >"$ERR"
      if ! timeout 90s clairctl report --out json "$CLAIR_TAG_REF" >"$TMP" 2>"$ERR"; then
        echo "clairctl failed for $CLAIR_TAG_REF:"
        sed -n '1,120p' "$ERR" || true
        rm -f "$TMP" "$ERR"
        continue
      fi
    else
      echo "clairctl failed for $CLAIR_REF:"
      sed -n '1,120p' "$ERR" || true
      rm -f "$TMP" "$ERR"
      continue
    fi
  fi

  if head -c 1 "$TMP" | grep -q '{'; then
    mv "$TMP" "$OUT"
    rm -f "$ERR" || true
    echo "→ $OUT"
  else
    echo "Non-JSON output — not saving."
    sed -n '1,60p' "$TMP" || true
    echo "(stderr)"
    sed -n '1,60p' "$ERR" || true
    rm -f "$TMP" "$ERR"
  fi
done

echo "All Clair reports at $OUT_DIR"
