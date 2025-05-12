#!/bin/bash
set -euo pipefail

# Text colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

INVESTIGATIONS_DIR="../pkg/investigations"
FAIL=0

is_informing() {
  local investigation_go="$1"
  local return_value

  return_value=$(
    grep -E --max-count=1 '^\s*func\s+\([^)]*)\s+InformingMode\(\)\s+bool' "$investigation_go" --after-context=1 \
      | tail --lines=1 \
      | grep -E -o '(true|false)'
    )

  if [[ "$return_value" == "false" ]]; then
    echo "Informing false for $investigation_go"
    return 1
  else
    echo "Informing true for $investigation_go"
    return 0
  fi
}

verify_rbac() {
  local yaml_file="$1"
  local write_actions=(create delete update patch)
  local actions

  actions=$(yq e '.rbac.clusterRoleRules[].verbs[]' "$yaml_file" 2>/dev/null || true)

  for action in $actions; do
    for w_action in "${write_actions[@]}"; do
      if [[ "$action" == "$w_action" ]]; then
        echo -e "${RED}Write action found: $action${NC}"
        return 1
      fi
    done
  done
  return 0
}

for inv in "$INVESTIGATIONS_DIR"/*/; do
  investigation_name="$(basename "$inv")"
  investigation_go="${inv}${investigation_name}.go"
  metadata_file="${inv}metadata.yaml"
  if [[ -f "$investigation_go" && -f "$metadata_file" ]]; then
    if is_informing "$investigation_go"; then
      if ! verify_rbac "$metadata_file"; then
        echo -e "${RED}[FAIL] $investigation_name RBAC contains a write action but is in informing mode${NC}"
        FAIL=1
      fi
    fi
  fi
done

if [[ "$FAIL" -eq 1 ]]; then
  echo -e "${RED}CHECK FAILED${NC}"
  exit 1
else
  echo -e "${GREEN}CHECK PASSED${NC}"
fi

