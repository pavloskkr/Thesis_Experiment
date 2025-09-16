#!/usr/bin/env bash
set -euo pipefail

SUBJECTS="${1:-subjects.yaml}"
OUT_DIR="reports/trivy"
mkdir -p "$OUT_DIR"

# simple YAML list reader (ignores comments/blank lines)
mapfile -t REFS < <(awk '/^subjects:/ {flag=1; next} flag && /^ *- / {gsub("^ *- *",""); print}' "$SUBJECTS" | sed '/^#/d;/^$/d')

echo "Found ${#REFS[@]} subjects."
for REF in "${REFS[@]}"; do
  # Trivy can scan by tag or digest. Use as-is.
  SAFE="$(echo "$REF" | sed -e 's|/|_|g' -e 's|:|_|g' -e 's|@|_|g')"
  OUT="$OUT_DIR/${SAFE}.json"
  echo "Trivy scanning $REF"
  trivy image --quiet --ignore-unfixed --format json --output "$OUT" "$REF"
  echo "→ $OUT"
done

echo "All Trivy reports at $OUT_DIR"
