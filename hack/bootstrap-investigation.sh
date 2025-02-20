#!/usr/bin/env bash

set -o nounset
set -o errexit
set -o pipefail

read -p "Enter the new investigation (package) name: " INVESTIGATION_NAME
if [[ "${INVESTIGATION_NAME}" == "" ]] ; then
	echo "Investigation name cannot be empty."
	exit 1
elif [[ "${INVESTIGATION_NAME}" =~ [^a-zA-Z0-9_] ]] ; then
	echo "Investigation name must be alphanumeric."
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
	return "TODO" // TODO: Add name
}

func (c *${STRUCT_NAME}) Description() string {
	return "TODO" // TODO: Add description
}

func (c *${STRUCT_NAME}) ShouldInvestigateAlert(alert string) bool {
	return strings.Contains(alert, "TODO") // TODO: Add alert string
}

func (c *${STRUCT_NAME}) IsExperimental() bool {
	return true // TODO: Modify experimental flag status
}

EOF

echo "${INVESTIGATION_NAME} created in ${INVESTIGATION_DIR}"

# Update registry.go to contain new investigation
if ! grep -q "${INVESTIGATION_NAME}" ../pkg/investigations/registry.go && ! grep -q "${STRUCT_NAME}" ../pkg/investigations/registry.go; then
	sed -i "/import (/a \\\t\"github.com/openshift/configuration-anomaly-detection/pkg/investigations/${INVESTIGATION_NAME}\"" ../pkg/investigations/registry.go
    sed -i "/var availableInvestigations = \[/a \\\t&${INVESTIGATION_NAME}.${STRUCT_NAME}{}," ../pkg/investigations/registry.go
    echo "${INVESTIGATION_NAME} added to registry.go"
else
    echo "${INVESTIGATION_NAME} already exists in registry.go"
fi
