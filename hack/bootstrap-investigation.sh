#!/usr/bin/env bash

set -e

SED="${SED:-sed}"

read -p "Enter the new investigation (package) name: " INVESTIGATION_NAME
if [[ "${INVESTIGATION_NAME}" == "" ]]; then
	echo "Investigation name cannot be empty."
	exit 1
elif [[ "${INVESTIGATION_NAME}" =~ [^a-zA-Z0-9_] ]]; then
	echo "Investigation name must be alphanumeric."
	exit 1
fi

read -p "Enter new investigation description: " INVESTIGATION_DESCRIPTION
if [[ "${INVESTIGATION_DESCRIPTION}" == "" ]]; then
	INVESTIGATION_DESCRIPTION="TODO"
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
cat <<EOF >"${INVESTIGATION_DIR}/README.md"
# ${INVESTIGATION_NAME} Investigation

${INVESTIGATION_DESCRIPTION}

## Testing

Refer to the [testing README](./testing/README.md) for instructions on testing this investigation

EOF

# Create testing/README.md file
cat <<EOF >"${INVESTIGATION_DIR}/testing/README.md"
# Testing ${INVESTIGATION_NAME} Investigation

TODO:
- Add a test script or test objects to this \`testing/\` directory for future maintainers to use
- Edit this README file and add detailed instructions on how to use the script/objects to recreate the conditions for the investigation. Be sure to include any assumptions or prerequisites about the environment (disable hive syncsetting, etc)
EOF

# Create metadata.yaml file
cat <<EOF >"${INVESTIGATION_DIR}/metadata.yaml"
name: ${INVESTIGATION_NAME}
rbac:
  roles: []
  clusterRoleRules: []
customerDataAccess: false

EOF

# Create boilerplate investigation file
cat <<EOF >"${INVESTIGATION_DIR}/${INVESTIGATION_NAME}.go"
// Package ${INVESTIGATION_NAME} contains...TODO
package ${INVESTIGATION_NAME}

import (
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
)

type Investigation struct{}

func (c *Investigation) Run(rb investigation.ResourceBuilder) (investigation.InvestigationResult, error) {
	result := investigation.InvestigationResult{}
	// TODO: Add additional builder configuration depending on your required resources using With...()
	r, err := rb.WithNotes().Build()
	if err != nil {
		return result, err
	}
	// TODO: Implement investigation logic here

	return result, r.PdClient.EscalateIncidentWithNote(r.Notes.String())
}

func (c *Investigation) Name() string {
	return "${INVESTIGATION_NAME}"
}
EOF

echo "${INVESTIGATION_NAME} created in ${INVESTIGATION_DIR}"
echo "metadata.yaml file created in ${INVESTIGATION_DIR}"

# Update registry.go to contain new investigation. Registration is still required so the
# investigation can be resolved by name at runtime (both webhook-triggered pipeline runs and
# manual runs) and so any config referencing it passes load-time validation.
if ! grep -q "${INVESTIGATION_NAME}" ../pkg/investigations/registry.go; then
	"${SED}" -i "/import (/a \\\t\"github.com/openshift/configuration-anomaly-detection/pkg/investigations/${INVESTIGATION_NAME}\"" ../pkg/investigations/registry.go
	"${SED}" -i "/var availableInvestigations = \[/a \\\t&${INVESTIGATION_NAME}.Investigation{}," ../pkg/investigations/registry.go
	echo "${INVESTIGATION_NAME} added to registry.go"
else
	echo "${INVESTIGATION_NAME} already exists in registry.go"
fi

echo -e "\n\nBootstrap complete. To enable this investigation, add it to the \`investigations\` list of the"
echo "relevant alert in the configuration file (app-interface) - either an existing alert or a new one. e.g.:"
cat <<EOF

	 cad_alerts: |
	       - alert_title: "example alert"  # substring matched against the incident title
	         name: "example"               # alert identifier: metrics label + alert-level filter's backplane remediation (RBAC)
	         when:                         # optional alert-level filter
	           field: HCP
	           operator: in
	           values: ["false"]
	         investigations:               # investigations to run for this alert; add the new one here
	           - "investigation1"
	           - "investigation2"
	           - "investigation3"
	           - "${INVESTIGATION_NAME}"

EOF
