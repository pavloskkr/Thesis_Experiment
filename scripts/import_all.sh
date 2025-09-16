#!/usr/bin/env bash
set -euo pipefail

TAR_DIR="${1:-./tars}"
SUBJECTS_FILE="${2:-subjects.yaml}"
PUSH_REG="${PUSH_REGISTRY:-localhost:5001}"

# Optional skopeo
if command -v skopeo >/dev/null 2>&1; then
  SKOPEO="skopeo"
else
  SKOPEO=""
fi

mkdir -p "$(dirname "$SUBJECTS_FILE")"
if ! grep -q '^subjects:' "$SUBJECTS_FILE" 2>/dev/null; then
  echo "subjects:" > "$SUBJECTS_FILE"
fi

shopt -s nullglob
tars=("$TAR_DIR"/*.tar)
if [ ${#tars[@]} -eq 0 ]; then
  echo "No .tar files found under $TAR_DIR" >&2
  exit 1
fi

for TAR in "${tars[@]}"; do
  echo "Loading $TAR ..."
  # Read docker load line-by-line to handle multi-tag TARs
  while IFS= read -r line; do
    echo "$line"
    SRC=""
    if [[ "$line" =~ ^Loaded[[:space:]]image:[[:space:]](.+)$ ]]; then
      SRC="${BASH_REMATCH[1]}"
    elif [[ "$line" =~ ^Loaded[[:space:]]image[[:space:]]ID:[[:space:]](sha256:[a-f0-9]+)$ ]]; then
      # Untagged image ID → fabricate a name from filename
      IMG_ID="${BASH_REMATCH[1]}"
      base="$(basename "$TAR" .tar)"
      name="${base//[^a-zA-Z0-9._-]/-}"
      docker tag "$IMG_ID" "$PUSH_REG/$name:manual"
      SRC="$PUSH_REG/$name:manual"
    else
      continue
    fi

    # Retag to our registry if needed
    if [[ "$SRC" != "$PUSH_REG/"* ]]; then
      # keep path after first slash (strip foreign registry)
      REPO="${SRC#*/}"
      docker tag "$SRC" "$PUSH_REG/$REPO"
      SRC="$PUSH_REG/$REPO"
    fi

    echo "Pushing $SRC ..."
    docker push "$SRC" >/dev/null

    # Determine digest
    if [ -n "$SKOPEO" ]; then
      DIGEST="$($SKOPEO inspect --no-tags "docker://$SRC" 2>/dev/null | awk -F\" '/Digest/ {print $4}')"
    else
      DIGEST="$(docker inspect --format='{{index .RepoDigests 0}}' "$SRC" | awk -F'@' '{print $2}')"
    fi
    if [ -z "${DIGEST:-}" ]; then
      echo "Failed to determine digest of $SRC" >&2
      exit 1
    fi

    REF="${SRC%@*}@${DIGEST}"
    echo "  → $REF"

    # Append once
    if ! grep -q -F "  - $REF" "$SUBJECTS_FILE"; then
      echo "  - $REF" >> "$SUBJECTS_FILE"
    fi
  done < <(docker load -i "$TAR")
done

echo "Done. Subjects updated: $SUBJECTS_FILE"
