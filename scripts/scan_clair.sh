#!/usr/bin/env bash
set -euo pipefail

# --- config & output dir (dated) ---
SUBJECTS="${1:-subjects.yaml}"
TODAY="$(date +%d-%m-%Y)"
OUT_DIR="reports/clair/${TODAY}"
mkdir -p "$OUT_DIR"

CLAIR_HEALTH="http://localhost:6061/metrics"
if ! curl -fsSL "$CLAIR_HEALTH" >/dev/null; then
  echo "Clair not healthy. Start it: docker compose -f clair/docker-compose.yml up -d"
  exit 1
fi

# Make Go clients (clairctl) trust our local CA bundle if present
if [ -f "$(pwd)/certs/ca-bundle.crt" ]; then
  export SSL_CERT_FILE="$(pwd)/certs/ca-bundle.crt"
fi

PUSH_REG="${PUSH_REGISTRY:-localhost:5001}"
PULL_REG_FOR_CLAIR="${PULL_REGISTRY_FOR_CLAIR:-host.docker.internal:5001}"

# --- helpers ---

# Normalize an image ref to NAME@DIGEST
lock_to_digest() {
  local ref="$1"
  if [[ "$ref" == *@sha256:* ]]; then
    echo "$ref"
    return 0
  fi
  # pull to ensure local resolver has it
  docker pull "$ref" >/dev/null
  local name; name="$(echo "$ref" | awk -F'[:@]' '{print $1}')"
  local dig;  dig="$(docker inspect --format='{{index .RepoDigests 0}}' "$ref" | awk -F'@' '{print $2}')"
  if [ -z "$dig" ]; then
    echo "ERR: could not resolve digest for $ref" >&2
    return 1
  fi
  echo "${name}@${dig}"
}

# If REF is a manifest index, rewrite to linux/amd64 child digest using docker (not skopeo)
child_amd64_from_index() {
  local ref="$1"
  # docker manifest inspect prints JSON (index or single manifest)
  local js; js="$(docker manifest inspect "$ref" 2>/dev/null || true)"
  if [ -z "$js" ]; then
    # can't inspect (private registry auth/TLS/etc.) — just keep ref
    echo "$ref"
    return 0
  fi

  # detect mediaType (quick & dirty)
  local mt; mt="$(printf '%s' "$js" | tr -d '\n' | sed -n 's/.*"mediaType"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"

  case "$mt" in
    application/vnd.docker.distribution.manifest.list.v2+json|application/vnd.oci.image.index.v1+json)
      # Try to extract linux/amd64 child digest (no jq)
      local child
      child="$(printf '%s' "$js" \
        | awk 'BEGIN{RS="\\{";FS="\\n"} /"platform"/ && /"os"[[:space:]]*:[[:space:]]*"linux"/ && /"architecture"[[:space:]]*:[[:space:]]*"amd64"/ {print "{"$0}' \
        | sed -n 's/.*"digest"[[:space:]]*:[[:space:]]*"\(sha256:[^"]*\)".*/\1/p' \
        | head -n1)"
      if [ -n "$child" ]; then
        local name_only="${ref%@*}"
        echo "${name_only}@${child}"
        return 0
      fi
      ;;
  esac

  # Not an index (or couldn’t find child) — keep as-is
  echo "$ref"
}

# Make image ref reachable from inside Clair container (host mapping)
map_for_clair_view() {
  local ref="$1"
  # Use the same var name as in your .env
  local host="${PULL_REGISTRY_FOR_CLAIR:-host.docker.internal:5001}"
  case "$ref" in
    localhost:5001/*)             echo "${ref/localhost:5001/$host}";;
    127.0.0.1:5001/*)             echo "${ref/127.0.0.1:5001/$host}";;
    registry:5000/*)              echo "${ref/registry:5000/$host}";;
    host.docker.internal:5001/*)  echo "$ref";;  # already good
    *)                            echo "$ref";;
  esac
}


safe_name() {
  echo "$1" | sed -e 's|/|_|g' -e 's|:|_|g' -e 's|@|_|g'
}

# --- read subjects ---
mapfile -t REFS < <(awk '/^subjects:/ {f=1; next} f && /^ *- / {sub(/^ *- */,""); print}' "$SUBJECTS" | sed '/^#/d;/^$/d')
echo "Found ${#REFS[@]} subjects."

# --- loop ---
for ORIG in "${REFS[@]}"; do
  # 1) lock to digest
  REF="$ORIG"
  if [[ "$REF" != *@sha256:* ]]; then
    echo "Resolving tag to digest: $REF"
    if ! REF="$(lock_to_digest "$REF")"; then
      echo "  ! skip $ORIG (digest resolution failed)"
      continue
    fi
  fi

  # Compute components we’ll reuse
# Compute components we’ll reuse (derive tag from the ORIGINAL ref, not from the digest)
# ORIG might be like: host:5001/repo:tag@sha256:...
BASE_NO_DIG="${ORIG%@*}"          # strip @sha256:... if present
if [[ "$BASE_NO_DIG" == *:* ]]; then
  ORIG_TAG="${BASE_NO_DIG##*:}"   # text after last ':' → the tag
else
  ORIG_TAG="latest"
fi

# NAME_ONLY = registry/repo (no tag, no digest) — take BASE_NO_DIG minus ':tag' if present
NAME_ONLY="${BASE_NO_DIG%:*}"     # host:5001/repo

# Build a clean tag ref and then map it to Clair’s viewpoint
TAG_REF="${NAME_ONLY}:${ORIG_TAG}"
CLAIR_TAG_REF="$(map_for_clair_view "$TAG_REF")"


  # 2) if multi-arch index, pick linux/amd64 child (best-effort)
  AMD64_REF="$(child_amd64_from_index "$REF")"
  if [[ "$AMD64_REF" != "$REF" ]]; then
    echo "  ↳ manifest list detected; using linux/amd64 child: ${AMD64_REF#*@}"
    REF="$AMD64_REF"
  fi

  # 3) map to Clair’s viewpoint (inside container)
  CLAIR_REF="$(map_for_clair_view "$REF")"
  CLAIR_TAG_REF="$(map_for_clair_view "$TAG_REF")"

  # 4) scan with fallback
  SAFE="$(safe_name "$ORIG")"
  OUT="${OUT_DIR}/${SAFE}.json"
  TMP="$(mktemp)"
  ERR="$(mktemp)"

  echo "Clair scanning (as seen by Clair): $CLAIR_REF"
  if timeout 90s clairctl report --out json "$CLAIR_REF" >"$TMP" 2>"$ERR"; then
    :
  else
    if grep -q 'MANIFEST_UNKNOWN' "$ERR"; then
      echo "  ↺ digest not resolvable by registry; retrying by tag: $CLAIR_TAG_REF"
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

  # Save only if it's JSON
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

