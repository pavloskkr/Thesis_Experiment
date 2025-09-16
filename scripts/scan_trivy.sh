#!/usr/bin/env bash
set -euo pipefail

SUBJ_FILE="${1:-subjects.yaml}"
REPORT_DIR="reports/trivy"
LOCAL_REG="${LOCAL_REGISTRY:-localhost:5001}"

mkdir -p "$REPORT_DIR"

# tiny YAML reader again
parse_yaml() { local s w fs; s='[[:space:]]*' w='[a-zA-Z0-9_./:@-]*' fs="$(echo @|tr @ '\034')"
sed -ne "s|^\($s\):|\1|" -e "s|^\($s\)\($w\)$s:$s[\"\']\(.*\)[\"\']$s\$|\1$fs\2$fs\3|p" -e "s|^\($s\)\($w\)$s:$s\(.*\)$s\$|\1$fs\2$fs\3|p"  $1 |
awk -F"$fs" '{indent=length($1)/2;vname[indent]=$2;for(i in vname){if(i>indent){delete vname[i]}} if(length($3)>0){vn="";for(i=0;i<indent;i++){vn=(vn)(vname[i])("_")} printf("%s%s%s=\"%s\"\n","Y_",vn,$2,$3)}}' ; }

eval "$(parse_yaml "$SUBJ_FILE")"

count=0; while true; do idx="Y_subjects_${count}_id"; [[ -n "${!idx:-}" ]] || break; count=$((count+1)); done
echo "Found $count subjects."

for i in $(seq 0 $((count-1))); do
  ID="${!Y_subjects_${i}_id}"
  TYPE="${!Y_subjects_${i}_type:-remote}"

  if [[ "$TYPE" == "remote" ]]; then
    REF="${!Y_subjects_${i}_ref}"
    docker pull "$REF" >/dev/null
    TARGET="$REF"
  else
    # tar path → ensure loaded + tagged like in Clair step
    LREPO="${!Y_subjects_${i}_local_repo}"
    LTAG="${!Y_subjects_${i}_local_tag:-exp}"
    TARGET="${LOCAL_REG}/${LREPO}:${LTAG}"
  fi

  OUT="reports/trivy/${ID}.json"
  echo "Trivy scanning ${TARGET}"
  trivy image --quiet --ignore-unfixed --format json --output "$OUT" "$TARGET"
  echo "→ ${OUT}"
done

echo "All Trivy reports under ${REPORT_DIR}/"
