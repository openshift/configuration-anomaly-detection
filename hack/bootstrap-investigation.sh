#!/usr/bin/env bash

set -e

read -p "Enter the new investigation (package) name: " INVESTIGATION_NAME
if [[ "${INVESTIGATION_NAME}" == "" ]] ; then
	echo "Investigation name cannot be empty."
	exit 1
elif [[ "${INVESTIGATION_NAME}" =~ [^a-zA-Z0-9_] ]] ; then
	echo "Investigation name must be alphanumeric."
	exit 1
fi

read -p "Enter new investigation description: " INVESTIGATION_DESCRIPTION
if [[ "${INVESTIGATION_DESCRIPTION}" == "" ]] ; then
	INVESTIGATION_DESCRIPTION="TODO"
fi

read -p "Should Investigate Alert (y/n): " INVESTIGATE_ALERT_BOOL
if [[ "${INVESTIGATE_ALERT_BOOL}" == "y" ]] ; then
	read -p "Investigation alert string: " INVESTIGATION_ALERT_STRING
	INVESTIGATION_ALERT="strings.Contains(alert, \"${INVESTIGATION_ALERT_STRING}\")"
elif [[ "${INVESTIGATE_ALERT_BOOL}" == "n" ]] ; then
	INVESTIGATION_ALERT="false"
else
	echo "Invalid input. Please enter 'y' or 'n'."
	exit 1
fi

INVESTIGATION_NAME=$(echo "${INVESTIGATION_NAME}" | tr '[:upper:]' '[:lower:]')

INVESTIGATION_DIR="../pkg/investigations/${INVESTIGATION_NAME}"

if [ -d "${INVESTIGATION_DIR}" ]; then
    echo "Investigation of name ${INVESTIGATION_NAME} already exists."
    exit 1
fi

mkdir -p "${INVESTIGATION_DIR}"
ls "${INVESTIGATION_DIR}"

touch "${INVESTIGATION_DIR}/${INVESTIGATION_NAME}.go"
touch "${INVESTIGATION_DIR}/metadata.yaml"
touch "${INVESTIGATION_DIR}/README.md"
mkdir "${INVESTIGATION_DIR}/testing/"

# Create README.md file
cat <<EOF > "${INVESTIGATION_DIR}/README.md"
# ${INVESTIGATION_NAME} Investigation

${INVESTIGATION_DESCRIPTION}

## Testing

Refer to the [testing README](./testing/README.md) for instructions on testing this investigation

EOF

# Create testing/README.md file
cat <<EOF > "${INVESTIGATION_DIR}/testing/README.md"
# Testing ${INVESTIGATION_NAME} Investigation
TODO:
- Add a test script or test objects to this `testing/` directory for future maintainers to use
- Edit this README file and add detailed instructions on how to use the script/objects to recreate the conditions for the investigation. Be sure to include any assumptions or prerequisites about the environment (disable hive syncsetting, etc)
EOF


# Create metadata.yaml file
cat <<EOF > "${INVESTIGATION_DIR}/metadata.yaml"
name: ${INVESTIGATION_NAME}
rbac:
  roles: []
  clusterRoleRules: []
customerDataAccess: false

EOF

# Create boilerplate investigation file
cat <<EOF > "${INVESTIGATION_DIR}/${INVESTIGATION_NAME}.go"
// Package ${INVESTIGATION_NAME} contains...TODO
package ${INVESTIGATION_NAME}

import (
	"strings"

	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
)

type Investigation struct{}

func (c *Investigation) Run(r *investigation.Resources) (investigation.InvestigationResult, error) {
	result := investigation.InvestigationResult{}

	// Initialize PagerDuty note writer
	notes := notewriter.New(r.Name, logging.RawLogger)
	defer func() { r.Notes = notes }()

	// TODO: Implement investigation logic here

	return result, r.PdClient.EscalateIncidentWithNote(notes.String())
}

func (c *Investigation) Name() string {
	return "${INVESTIGATION_NAME}"
}

func (c *Investigation) Description() string {
	return "${INVESTIGATION_DESCRIPTION}"
}

func (c *Investigation) ShouldInvestigateAlert(alert string) bool {
	return ${INVESTIGATION_ALERT}
}

func (c *Investigation) IsExperimental() bool {
	// TODO: Update to false when graduating to production.
	return true
}

func (c *Investigation) InformingMode(flag bool) bool {
	informingOnly := true // TODO: Update to false when promoting investigation to "actioning mode" (See README)
	return informingOnly || flag
}

EOF

echo "${INVESTIGATION_NAME} created in ${INVESTIGATION_DIR}"
echo "metadata.yaml file created in ${INVESTIGATION_DIR}"

# Update registry.go to contain new investigation
if ! grep -q "${INVESTIGATION_NAME}" ../pkg/investigations/registry.go && ! grep -q "${INVESTIGATION_NAME}" ../pkg/investigations/registry.go; then
	sed -i "/import (/a \\\t\"github.com/openshift/configuration-anomaly-detection/pkg/investigations/${INVESTIGATION_NAME}\"" ../pkg/investigations/registry.go
    sed -i "/var availableInvestigations = \[/a \\\t&${INVESTIGATION_NAME}.Investigation{}," ../pkg/investigations/registry.go
    echo "${INVESTIGATION_NAME} added to registry.go"
else
    echo "${INVESTIGATION_NAME} already exists in registry.go"
fi
