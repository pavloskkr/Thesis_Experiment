#!/usr/bin/env bash
set -euo pipefail

# Ensure fresh dated folders are created automatically by scan_* scripts
./scripts/scan_trivy.sh subjects.yaml
./scripts/scan_clair.sh subjects.yaml

# Aggregate into out/<date>
python3 scripts/aggregate.py reports out
