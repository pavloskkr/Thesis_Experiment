#!/usr/bin/env bash
set -euo pipefail

# Config
SUBJ_FILE="${1:-subjects.yaml}"
REPORT_DIR="reports/clair"
LOCAL_REG="${LOCAL_REGISTRY:-localhost:5001}" # change to host.docker.internal:5001 if using skopeo-in-container on Windows
CLAIR_HEALTH="http://localhost:6061/metrics"

mkdir -p "$REPORT_DIR"

# quick health check
if ! curl -fsSL "$CLAIR_HEALTH" >/dev/null; then
  echo "Clair not healthy on $CLAIR_HEALTH. Start it with: docker compose -f clair/docker-compose.yml up -d"
  exit 1
fi

# very small YAML reader (expects lines like 'type:' and 'ref:' etc.)
parse_yaml() { # $1 file, $2 prefix
  local s w fs
  s='[[:space:]]*' w='[a-zA-Z0-9_./:@-]*' fs="$(echo @|tr @ '\034')"
  sed -ne "s|^\($s\):|\1|" \
      -e "s|^\($s\)\($w\)$s:$s[\"\']\(.*\)[\"\']$s\$|\1$fs\2$fs\3|p" \
      -e "s|^\($s\)\($w\)$s:$s\(.*\)$s\$|\1$fs\2$fs\3|p"  $1 |
  awk -F"$fs" '{
     indent = length($1)/2;
     vname[indent] = $2;
     for (i in vname) { if (i > indent) { delete vname[i] } }
     if (length($3) > 0) {
       vn=""; for (i=0; i<indent; i++) { vn=(vn)(vname[i])("_") }
       printf("%s%s%s=\"%s\"\n", "'$2'", vn, $2, $3);
     }
  }'
}

# read YAML into env-like variables
eval "$(parse_yaml "$SUBJ_FILE" "Y_")"

# Count entries
count=0
while true; do
  idx="Y_subjects_${count}_id"
  [[ -n "${!idx:-}" ]] || break
  count=$((count+1))
done

echo "Found $count subjects."

for i in $(seq 0 $((count-1))); do
  id_var="Y_subjects_${i}_id"
  type_var="Y_subjects_${i}_type"
  ref_var="Y_subjects_${i}_ref"
  path_var="Y_subjects_${i}_path"
  lrepo_var="Y_subjects_${i}_local_repo"
  ltag_var="Y_subjects_${i}_local_tag"

  ID="${!id_var}"; TYPE="${!type_var:-remote}"
  echo "=== [$ID] type=$TYPE ==="

  LOCAL_REF=""
  if [[ "$TYPE" == "remote" ]]; then
    REF="${!ref_var}"
    # pull & resolve digest for determinism
    docker pull "$REF" >/dev/null
    DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "$REF" | awk -F'@' '{print $2}')
    NAME=$(echo "$REF" | awk -F'[:@]' '{print $1}')
    # mirror to local registry (tag push)
    TAG="locked"
    docker tag "${NAME}@${DIGEST}" "${LOCAL_REG}/${NAME#*/}:${TAG}"
    docker push "${LOCAL_REG}/${NAME#*/}:${TAG}" >/dev/null
    # use the manifest digest from the local registry
    LOCAL_DIGEST=$(skopeo inspect --no-tags "docker://${LOCAL_REG}/${NAME#*/}:${TAG}" 2>/dev/null | awk -F\" '/Digest/ {print $4}')
    LOCAL_REF="${LOCAL_REG}/${NAME#*/}@${LOCAL_DIGEST:-$DIGEST}"

  elif [[ "$TYPE" == "tar" ]]; then
    PATH_TAR="${!path_var}"
    LREPO="${!lrepo_var}"
    LTAG="${!ltag_var:-exp}"
    docker load -i "$PATH_TAR" >/dev/null
    docker tag "${LREPO}:${LTAG}" "${LOCAL_REG}/${LREPO}:${LTAG}"
    docker push "${LOCAL_REG}/${LREPO}:${LTAG}" >/dev/null
    LOCAL_DIGEST=$(skopeo inspect --no-tags "docker://${LOCAL_REG}/${LREPO}:${LTAG}" 2>/dev/null | awk -F\" '/Digest/ {print $4}')
    LOCAL_REF="${_
