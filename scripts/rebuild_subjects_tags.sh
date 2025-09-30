#!/usr/bin/env bash
set -euo pipefail

# Build a full subjects.yaml listing *every tag* for repos you care about.

REG_URL="${REG_URL:-https://localhost:5001}"     # for curl
REG_HOST="${REG_HOST:-localhost:5001}"           # used in image refs
CA="${CA_CERT:-certs/ca.crt}"

# Keep only certain namespaces
NS_KEEP_REGEX="${NS_KEEP_REGEX:-^(gcp/|istio/|org/|library/)}"

OUT_FILE="${1:-subjects.yaml}"

# --- sanity ---
echo ">> Checking registry at $REG_URL ..."
curl -fsS --cacert "$CA" "$REG_URL/v2/" >/dev/null

# --- fetch catalog (use n=1000 to avoid 400) ---
echo ">> Fetching catalog..."
CAT_JSON="$(curl -fsS --cacert "$CA" "$REG_URL/v2/_catalog?n=1000")"

# Parse repositories array (jq if available, otherwise sed)
if command -v jq >/dev/null 2>&1; then
  mapfile -t REPOS < <(printf '%s\n' "$CAT_JSON" | jq -r '.repositories[]?')
else
  mapfile -t REPOS < <(printf '%s\n' "$CAT_JSON" \
    | tr -d '\n ' | sed -n 's/.*"repositories":\[\([^]]*\)\].*/\1/p' \
    | tr ',' '\n' | sed -e 's/"//g' -e '/^$/d')
fi

# Filter namespaces
mapfile -t REPOS < <(printf '%s\n' "${REPOS[@]}" | grep -E "$NS_KEEP_REGEX" || true)
if [[ ${#REPOS[@]} -eq 0 ]]; then
  echo "ERR: No repositories matched '$NS_KEEP_REGEX'." >&2
  exit 1
fi

# --- build subjects list with ALL tags ---
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
echo "subjects:" > "$TMP"

for r in "${REPOS[@]}"; do
  TAGS_JSON="$(curl -fsS --cacert "$CA" "$REG_URL/v2/$r/tags/list" || true)"
  # parse tags
  if command -v jq >/dev/null 2>&1; then
    mapfile -t TAGS < <(printf '%s\n' "$TAGS_JSON" | jq -r '.tags[]?' | sed '/^null$/d')
  else
    mapfile -t TAGS < <(printf '%s\n' "$TAGS_JSON" | tr -d '\n ' \
      | sed -n 's/.*"tags":\[\([^]]*\)\].*/\1/p' \
      | tr ',' '\n' | sed -e 's/"//g' -e '/^$/d')
  fi

  if [[ ${#TAGS[@]} -eq 0 ]]; then
    # no tags (maybe digest-only or empty) — skip
    continue
  fi

  for t in "${TAGS[@]}"; do
    echo "  - ${REG_HOST}/${r}:${t}" >> "$TMP"
  done
done

mv "$TMP" "$OUT_FILE"
echo "Rebuilt $OUT_FILE with all tags."
