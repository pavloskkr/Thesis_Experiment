#!/usr/bin/env bash
set -euo pipefail

# Mirrors remote image refs to a local registry and appends locked refs to subjects.yaml
# Usage:
#   scripts/mirror_to_local.sh seeds.txt             # one ref per line
#   scripts/mirror_to_local.sh -                     # read refs from stdin
#   REMOTE_SUBJECTS="docker.io/library/nginx:1.29.1 istio/examples-bookinfo-ratings-v2:1.20.3" \
#     scripts/mirror_to_local.sh                     # read refs from env var
#
# Env:
#   PUSH_REGISTRY (default: localhost:5001)
#   SUBJECTS_FILE (default: subjects.yaml)
#   PLATFORM      (default: linux/amd64)
#
# Notes:
#  - Keeps repo path; e.g. "docker.io/library/nginx:1.29.1" → "localhost:5001/library/nginx:1.29.1"
#  - Locks subjects.yaml to the pushed digest: repo:tag@sha256:...
#  - Safe to rerun; avoids duplicate lines in subjects.yaml
#  - Works with self-signed CA if your Docker daemon trusts it (as in your current setup).

PUSH_REG="${PUSH_REGISTRY:-localhost:5001}"
SUBJECTS_FILE="${SUBJECTS_FILE:-subjects.yaml}"
PLATFORM="${PLATFORM:-linux/amd64}"

INPUT="${1:-${REMOTE_SUBJECTS:-}}"

echo "# Push endpoint: https://${PUSH_REG}"
echo "# Subjects file: ${SUBJECTS_FILE}"
echo "# Target platform: ${PLATFORM}"

# --- ensure subjects.yaml header ---
mkdir -p "$(dirname "$SUBJECTS_FILE")"
if ! grep -qE '^[[:space:]]*subjects:' "$SUBJECTS_FILE" 2>/dev/null; then
  echo "subjects:" > "$SUBJECTS_FILE"
fi

# --- read refs into array ---
read_refs() {
  clean() {
    sed -e 's/#.*$//' \
        -e 's/\r$//' \
        -e 's/^[[:space:]]\+//' -e 's/[[:space:]]\+$//' \
        -e '/^$/d'
  }
  if [[ -n "$INPUT" && "$INPUT" != "-" && -f "$INPUT" ]]; then
    clean < "$INPUT"
  elif [[ "$INPUT" == "-" ]]; then
    clean
  elif [[ -n "$INPUT" && "$INPUT" != "-" ]]; then
    printf '%s\n' "$INPUT" | clean
  else
    echo "ERROR: provide a file path, '-' for stdin, or set REMOTE_SUBJECTS." >&2
    exit 2
  fi
}


mapfile -t REFS < <(read_refs)

if [[ ${#REFS[@]} -eq 0 ]]; then
  echo "No refs found." >&2
  exit 1
fi

echo "# Found ${#REFS[@]} ref(s):"
for r in "${REFS[@]}"; do echo "  - $r"; done

# --- helpers ---
append_unique_ref() {
  local ref="$1"
  ref="${ref%% *}" # strip accidental tails
  if ! grep -q -F "  - $ref" "$SUBJECTS_FILE"; then
    echo "  - $ref" >> "$SUBJECTS_FILE"
  fi
}

# parse digest from docker push output
get_digest_from_pushlog() {
  awk '
    /digest:[[:space:]]*sha256:[0-9a-f]+/ {
      for (i=1;i<=NF;i++) if ($i ~ /^sha256:[0-9a-f]+$/) last=$i
    }
    END { if (last!="") print last }
  ' "$1"
}

# normalize "host/path:tag" → "path:tag" (drop host)
drop_registry_host() {
  local s="$1"
  # If there is at least one '/', remove everything up to the first '/'
  if [[ "$s" == */* ]]; then
    echo "${s#*/}"
  else
    echo "$s"
  fi
}

# --- main loop ---
for SRC in "${REFS[@]}"; do
  # If ref already includes a digest, keep it for the pull, but we’ll tag to :tag form for push
  echo
  echo "==> Processing: $SRC"

  # Ensure we have a tag if none provided (avoid implicit 'latest')
  if [[ "$SRC" != *":"* && "$SRC" != *@sha256:* ]]; then
    SRC="${SRC}:latest"
  fi

  # Pull specific platform to avoid multi-arch ambiguity
  echo "Pulling: $SRC (platform ${PLATFORM})"
  if ! docker pull --platform="${PLATFORM}" "$SRC" >/dev/null; then
    echo "  ! pull failed: $SRC" >&2
    continue
  fi

  # Compute repo:tag (strip any @sha256 suffix) and drop foreign registry host
  NAME_TAG="${SRC%@sha256:*}"
  PATH_TAG="$(drop_registry_host "$NAME_TAG")"      # e.g., library/nginx:1.29.1
  DEST="${PUSH_REG}/${PATH_TAG}"                    # e.g., localhost:5001/library/nginx:1.29.1

  echo "Tagging → $DEST"
  docker tag "$NAME_TAG" "$DEST"

  echo "Pushing: $DEST"
  push_log="$(mktemp)"
  if ! docker push "$DEST" | tee "$push_log" >/dev/null; then
    echo "  ! push failed: $DEST" >&2
    rm -f "$push_log"
    continue
  fi

  DIGEST="$(get_digest_from_pushlog "$push_log" || true)"
  rm -f "$push_log"

  if [[ -z "$DIGEST" ]]; then
    # Fallback: resolve from local inspect of RepoDigests for our registry
    DIGEST="$(docker inspect --format='{{range .RepoDigests}}{{println .}}{{end}}' "$DEST" \
      | grep -F "${PUSH_REG}/" \
      | awk -F'@' '{print $2}' \
      | tail -n1 || true)"
  fi

  DIGEST="${DIGEST%% *}"

  if [[ -z "$DIGEST" ]]; then
    echo "  ! could not determine digest for $DEST" >&2
    continue
  fi

  LOCKED="${DEST%@*}@${DIGEST}"
  echo "  → appended: $LOCKED"
  append_unique_ref "$LOCKED"
done

echo
echo "# Done. Updated ${SUBJECTS_FILE}"
