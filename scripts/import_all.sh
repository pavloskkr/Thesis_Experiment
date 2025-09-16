#!/usr/bin/env bash
set -euo pipefail

REGISTRY="${REGISTRY:-localhost:5000}"
TAR_DIR="${1:-./tars}"
SUBJECTS_FILE="${2:-subjects.yaml}"

# Start a local registry if not running
if ! docker ps --format '{{.Names}}' | grep -q '^registry$'; then
  echo "Starting local registry at $REGISTRY ..."
  docker run -d --restart=always -p 5000:5000 --name registry registry:2 >/dev/null
fi

mkdir -p "$(dirname "$SUBJECTS_FILE")"
echo "subjects:" > "$SUBJECTS_FILE"

shopt -s nullglob
tars=("$TAR_DIR"/*.tar)
if [ ${#tars[@]} -eq 0 ]; then
  echo "No .tar files found under $TAR_DIR" >&2
  exit 1
fi

strip_registry() {
  # Remove leading registry domain (up to first '/')
  echo "$1" | sed 's|^[^/]*/||'
}

for TAR in "${tars[@]}"; do
  echo "Loading $TAR ..."
  OUT="$(docker load -i "$TAR")" || { echo "docker load failed for $TAR"; exit 1; }
  echo "$OUT"

  SRC=""
  if [[ "$OUT" =~ Loaded[[:space:]]image:[[:space:]](.+) ]]; then
    SRC="${BASH_REMATCH[1]}"
  elif [[ "$OUT" =~ Loaded[[:space:]]image[[:space:]]ID:[[:space:]](sha256:[a-f0-9]+) ]]; then
    # No tag in the tar; fabricate a name:tag from filename
    IMG_ID="${BASH_REMATCH[1]}"
    base="$(basename "$TAR" .tar)"
    name="${base//[^a-zA-Z0-9._-]/-}"
    SRC="$IMG_ID"
    docker tag "$IMG_ID" "$REGISTRY/$name:manual"
    DEST="$REGISTRY/$name:manual"
    docker push "$DEST" >/dev/null
    DIGEST="$(docker inspect --format='{{index .RepoDigests 0}}' "$DEST")"
    echo "  → $DEST @ $DIGEST"
    echo "  - $DIGEST" >> "$SUBJECTS_FILE"
    continue
  else
    echo "Could not parse docker load output for $TAR" >&2
    exit 1
  fi

  # Retag to local registry
  REPO_NO_REG="$(strip_registry "$SRC")"
  DEST="$REGISTRY/$REPO_NO_REG"
  echo "Tagging $SRC → $DEST"
  docker tag "$SRC" "$DEST"

  # Push and capture digest
  docker push "$DEST" >/dev/null
  DIGEST="$(docker inspect --format='{{index .RepoDigests 0}}' "$DEST")"
  echo "  → pushed @ $DIGEST"
  echo "  - $DIGEST" >> "$SUBJECTS_FILE"
done

echo "Done. Subjects written to $SUBJECTS_FILE"
