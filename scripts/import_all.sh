#!/usr/bin/env bash
set -euo pipefail

# Where your TARs live (change if you want)
TAR_DIR="${1:-./tars}"
SUBJECTS_FILE="${2:-subjects.yaml}"

# host-side push endpoint (this is the registry service above, published to 5001)
PUSH_REG="${PUSH_REGISTRY:-localhost:5001}"

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
  OUT="$(docker load -i "$TAR")"
  echo "$OUT"

  # docker load output has two variants
  SRC=""
  if [[ "$OUT" =~ Loaded[[:space:]]image:[[:space:]](.+) ]]; then
    SRC="${BASH_REMATCH[1]}"
  elif [[ "$OUT" =~ Loaded[[:space:]]image[[:space:]]ID:[[:space:]](sha256:[a-f0-9]+) ]]; then
    # No tag in TAR → fabricate a name:tag from filename
    IMG_ID="${BASH_REMATCH[1]}"
    base="$(basename "$TAR" .tar)"
    name="${base//[^a-zA-Z0-9._-]/-}"
    docker tag "$IMG_ID" "$PUSH_REG/$name:manual"
    SRC="$PUSH_REG/$name:manual"
  else
    echo "Could not parse docker load output for $TAR" >&2
    exit 1
  fi

  # if loaded with a source name not pointing to our registry, retag
  if [[ "$SRC" != "$PUSH_REG/"* ]]; then
    # strip leading registry if any
    REPO="${SRC#*/}"
    docker tag "$SRC" "$PUSH_REG/$REPO"
    SRC="$PUSH_REG/$REPO"
  fi

  echo "Pushing $SRC ..."
  docker push "$SRC" >/dev/null

  # lock to digest and append to subjects.yaml
  DIGEST="$(skopeo inspect --no-tags "docker://$SRC" 2>/dev/null | awk -F\" '/Digest/ {print $4}')"
  if [ -z "$DIGEST" ]; then
    DIGEST="$(docker inspect --format='{{index .RepoDigests 0}}' "$SRC" | awk -F'@' '{print $2}')"
  fi
  if [ -z "$DIGEST" ]; then
    echo "Failed to determine digest of $SRC" >&2
    exit 1
  fi
  REF="${SRC%@*}@${DIGEST}"
  echo "  → $REF"
  # append if not already present
  if ! grep -q -F "  - $REF" "$SUBJECTS_FILE"; then
    echo "  - $REF" >> "$SUBJECTS_FILE"
  fi
done

echo "Done. Subjects updated: $SUBJECTS_FILE"
