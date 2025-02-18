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
	INVESTIGATION_ALERT="strings.Contains(alert, ${INVESTIGATION_ALERT_STRING})"
elif [[ "${INVESTIGATE_ALERT_BOOL}" == "n" ]] ; then
	INVESTIGATION_ALERT="false"
else
	echo "Invalid input. Please enter 'y' or 'n'."
	exit 1
fi

INVESTIGATION_NAME=$(echo "${INVESTIGATION_NAME}" | tr '[:upper:]' '[:lower:]')
STRUCT_NAME=$(echo "${INVESTIGATION_NAME}" | awk '{print toupper(substr($0,1,1))tolower(substr($0,2))}')

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

# Create README.md file
cat <<EOF > "${INVESTIGATION_DIR}/README.md"
# ${INVESTIGATION_NAME} Investigation

*TODO*

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

type ${STRUCT_NAME} struct{}

func (c *${STRUCT_NAME}) Run(r *investigation.Resources) (investigation.InvestigationResult, error) {
	result := investigation.InvestigationResult{}

	// Initialize PagerDuty note writer
	notes := notewriter.New(r.Name, logging.RawLogger)

	// TODO:
	// Implement investigation logic here

	return result, r.PdClient.EscalateIncidentWithNote(notes.String())
}

func (c *${STRUCT_NAME}) Name() string {
	return "${INVESTIGATION_NAME}"
}

func (c *${STRUCT_NAME}) Description() string {
	return "${INVESTIGATION_DESCRIPTION}"
}

func (c *${STRUCT_NAME}) ShouldInvestigateAlert(alert string) bool {
	return ${INVESTIGATION_ALERT}
}

func (c *${STRUCT_NAME}) IsExperimental() bool {
	return true // Set true by default
}

EOF

echo "${INVESTIGATION_NAME} created in ${INVESTIGATION_DIR}"
echo "metadata.yaml file created in ${INVESTIGATION_DIR}"

# Update registry.go to contain new investigation
if ! grep -q "${INVESTIGATION_NAME}" ../pkg/investigations/registry.go && ! grep -q "${STRUCT_NAME}" ../pkg/investigations/registry.go; then
	sed -i "/import (/a \\\t\"github.com/openshift/configuration-anomaly-detection/pkg/investigations/${INVESTIGATION_NAME}\"" ../pkg/investigations/registry.go
    sed -i "/var availableInvestigations = \[/a \\\t&${INVESTIGATION_NAME}.${STRUCT_NAME}{}," ../pkg/investigations/registry.go
    echo "${INVESTIGATION_NAME} added to registry.go"
else
    echo "${INVESTIGATION_NAME} already exists in registry.go"
fi
