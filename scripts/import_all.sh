#!/usr/bin/env bash
set -euo pipefail

# --- Config -------------------------------------------------------------------
TAR_DIR="${1:-./tars}"
SUBJECTS_FILE="${2:-subjects.yaml}"
PUSH_REG="${PUSH_REGISTRY:-localhost:5001}"

echo "# Using push endpoint: https://${PUSH_REG}"
echo "# Scanning archives under: ${TAR_DIR}"

# Ensure subjects.yaml has a header
mkdir -p "$(dirname "$SUBJECTS_FILE")"
if ! grep -qE '^[[:space:]]*subjects:' "$SUBJECTS_FILE" 2>/dev/null; then
  echo "subjects:" > "$SUBJECTS_FILE"
fi

# Find archives
shopt -s nullglob
tars=("$TAR_DIR"/*.tar "$TAR_DIR"/*.tgz "$TAR_DIR"/*.tar.gz)
# Drop any non-matches
tars=("${tars[@]/#$(printf '%q' "$TAR_DIR")\/*(N)}")

if [ ${#tars[@]} -eq 0 ]; then
  echo "# Found 0 archive(s) in ${TAR_DIR}"
  echo "No archives found under ${TAR_DIR} (looked for *.tar, *.tar.gz, *.tgz)"
  exit 1
fi

echo "# Found ${#tars[@]} archive(s) in ${TAR_DIR}:"
for f in "${tars[@]}"; do
  echo "  - $(basename "$f")"
done

# --- Helpers ------------------------------------------------------------------
# Extract sha256 digest token from a docker push log file
get_digest_from_pushlog() {
  # prints the last "sha256:..." token found (without trailing text)
  awk '
    /digest:[[:space:]]*sha256:[0-9a-f]+/ {
      for (i=1;i<=NF;i++) if ($i ~ /^sha256:[0-9a-f]+$/) last=$i
    }
    END { if (last!="") print last }
  ' "$1"
}

append_unique_ref() {
  local ref="$1"
  # strip accidental " size: NNN" tails defensively
  ref="${ref%% *}"
  if ! grep -q -F "  - $ref" "$SUBJECTS_FILE"; then
    echo "  - $ref" >> "$SUBJECTS_FILE"
  fi
}

# --- Main ---------------------------------------------------------------------
for TAR in "${tars[@]}"; do
  echo "Loading $TAR ..."
  # Use process substitution so we can parse *all* 'Loaded image:' lines
  while IFS= read -r line; do
    echo "$line"

    SRC=""
    if [[ "$line" =~ ^Loaded[[:space:]]image:[[:space:]](.+)$ ]]; then
      SRC="${BASH_REMATCH[1]}"
    elif [[ "$line" =~ ^Loaded[[:space:]]image[[:space:]]ID:[[:space:]](sha256:[a-f0-9]+)$ ]]; then
      # Untagged image ID → fabricate a name:tag from filename
      IMG_ID="${BASH_REMATCH[1]}"
      base="$(basename "$TAR")"
      base="${base%.tar}"
      base="${base%.tgz}"
      base="${base%.tar.gz}"
      name="${base//[^a-zA-Z0-9._-]/-}"
      docker tag "$IMG_ID" "$PUSH_REG/$name:manual"
      SRC="$PUSH_REG/$name:manual"
    else
      # other docker load chatter; ignore
      continue
    fi

    # If the loaded image is not already pointed at our registry, retag it
    if [[ "$SRC" != "$PUSH_REG/"* ]]; then
      # Keep the path after the first slash (drop any foreign registry/host)
      REPO="${SRC#*/}"
      docker tag "$SRC" "$PUSH_REG/$REPO"
      SRC="$PUSH_REG/$REPO"
    fi

    echo "Pushing $SRC ..."
    push_log="$(mktemp)"
    # Show progress to terminal *and* capture to a log for digest parsing
    if ! docker push "$SRC" | tee "$push_log" >/dev/null; then
      echo "Push failed for $SRC" >&2
      rm -f "$push_log"
      continue
    fi

    # Prefer parsing digest from push output (works even with custom CA)
    DIGEST="$(get_digest_from_pushlog "$push_log" || true)"
    rm -f "$push_log"

    # Fallback: inspect local image object for RepoDigests entry
    if [ -z "$DIGEST" ]; then
      DIGEST="$(docker inspect --format='{{range .RepoDigests}}{{println .}}{{end}}' "$SRC" \
        | grep -F "${PUSH_REG}/" \
        | awk -F'@' '{print $2}' \
        | tail -n1 || true)"
    fi

    # Trim any stray tails like " size: 1994"
    DIGEST="${DIGEST%% *}"

    if [ -z "$DIGEST" ]; then
      echo "Failed to determine digest of $SRC" >&2
      continue
    fi

    # Compose a stable ref with the original name+tag but with locked digest
    # (avoid accidental "@..." from RepoDigests)
    NAME_TAG="${SRC%@*}"         # strip any accidental @sha256 if present
    REF="${NAME_TAG}@${DIGEST}"
    echo "  → $REF"

    append_unique_ref "$REF"
  done < <(docker load -i "$TAR")
done

echo
echo "Done. Subjects updated: $SUBJECTS_FILE"
