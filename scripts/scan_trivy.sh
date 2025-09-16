#!/usr/bin/env bash
set -euo pipefail

SUBJ_FILE="${1:-subjects.yaml}"
REPORT_DIR="reports/trivy"
mkdir -p "$REPORT_DIR"

# Decide native vs dockerized Trivy
if command -v trivy >/dev/null 2>&1; then
  echo "Using native Trivy."
  RUN_NATIVE=1
else
  echo "Trivy not found; using Dockerized Trivy."
  RUN_NATIVE=0
fi

# Normalize host paths for Docker Desktop on Windows (Git Bash)
if [[ "${OSTYPE:-}" == "msys" || "${OSTYPE:-}" == "cygwin" ]]; then
  HOST_PWD="$(pwd -W)"
else
  HOST_PWD="$PWD"
fi

# Build docker run prefix
if [[ "$RUN_NATIVE" -eq 0 ]]; then
  DOCKER_TRIVY=(docker run --rm
    -e TRIVY_CACHE_DIR=/root/.cache/trivy
    -v "$HOST_PWD:/workspace"
    -v "$HOME/.cache/trivy:/root/.cache/trivy"
    -w /workspace
    aquasec/trivy:latest)
fi

# Read subjects list
mapfile -t REFS < <(awk '/^subjects:/ {f=1; next} f && /^ *- / {sub(/^ *- */,""); print}' "$SUBJ_FILE" | sed '/^#/d;/^$/d')
echo "Found ${#REFS[@]} subjects."

for REF in "${REFS[@]}"; do
  TARGET="$REF"

  # If Trivy runs in a container, rewrite localhost → host.docker.internal
  if [[ "$RUN_NATIVE" -eq 0 ]]; then
    case "$TARGET" in
      localhost:*)  TARGET="host.docker.internal:${TARGET#localhost:}";;
      127.0.0.1:*)  TARGET="host.docker.internal:${TARGET#127.0.0.1:}";;
    esac
  fi

  # Add --insecure when we’re hitting your local plain-HTTP registry
  INSECURE=()
  case "$TARGET" in
    host.docker.internal:5001/*|localhost:5001/*|127.0.0.1:5001/*)
      INSECURE+=(--insecure)
      ;;
  esac

  SAFE="$(echo "$REF" | sed -e 's|/|_|g' -e 's|:|_|g' -e 's|@|_|g')"
  OUT="$REPORT_DIR/${SAFE}.json"
  echo "Trivy scanning $TARGET"

  if [[ "$RUN_NATIVE" -eq 1 ]]; then
    trivy image --quiet --ignore-unfixed "${INSECURE[@]}" --format json --output "$OUT" "$TARGET"
  else
    "${DOCKER_TRIVY[@]}" image --quiet --ignore-unfixed "${INSECURE[@]}" --format json --output "$OUT" "$TARGET"
  fi

  echo "→ $OUT"
done

echo "All Trivy reports at $REPORT_DIR"
