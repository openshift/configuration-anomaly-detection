#!/usr/bin/env bash
set -euo pipefail

# Text colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

base_sha=$(echo "$CLONEREFS_OPTIONS" | grep -o '"base_sha":"[^"]*"' | cut -d':' -f2 | tr -d '"' )

if [[ -z "$base_sha" ]]; then
	echo -e "${RED}Could not obtain base_sha"
	exit 1
fi

# Obtaining instances of files added in the PR
diff_files=$(git diff --name-status "$base_sha" HEAD | grep '^A' | awk '{print $2}')

# Filter to relevant directory (investigations folder)
investigations=$(echo "$diff_files" | grep '^pkg/investigations/' || true)
if [ -z "$investigations" ]; then
	echo -e "${GREEN}[PASS] PR does not contain any new files within the \`pkg/investigations\` directory${NC}"
	exit 0
fi

for file in $investigations; do
	if [[ "$file" =~ ^pkg/investigations/([^/]+)/([^/]+)\.go$ ]]; then

		if echo "$file" | grep -q "test"; then
			break
		fi

		inv_name="${BASH_REMATCH[1]}"
		inv_dir=$(dirname "$file")
		expected_test_file="${inv_dir}/${inv_name}_test.go"

		echo "Found new investigation file: $file, expecting unit test: $expected_test_file"

		if echo "$diff_files" | grep -xq "$expected_test_file"; then
			echo "Successfully found test file."
		else
			echo "Failed to locate test file"
			echo -e "${RED}[FAIL] Added investigation '$inv_name' is missing a \`${inv_name}_test.go\` file.${NC}"
			exit 1
		fi
	fi
done

echo -e "${GREEN}[PASS] Added investigation(s) have a corresponding test file${NC}"
exit 0
