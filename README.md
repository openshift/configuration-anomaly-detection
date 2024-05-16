[![Go Report Card](https://goreportcard.com/badge/github.com/openshift/configuration-anomaly-detection)](https://goreportcard.com/report/github.com/openshift/configuration-anomaly-detection) [![PkgGoDev](https://pkg.go.dev/badge/github.com/openshift/configuration-anomaly-detection)](https://pkg.go.dev/github.com/openshift/configuration-anomaly-detection)
[![codecov](https://codecov.io/gh/openshift/configuration-anomaly-detection/branch/main/graph/badge.svg)](https://codecov.io/gh/openshift/configuration-anomaly-detection)
[![License](https://img.shields.io/:license-apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)

----

- [Configuration Anomaly Detection](#configuration-anomaly-detection)
  - [About](#about)
  - [Contributing](#contributing)
    - [Adding a new investigation](#adding-a-new-investigation)
  - [Testing locally](#testing-locally)
    - [Pre-requirements](#pre-requirements)
    - [Running cadctl for an incident ID](#running-cadctl-for-an-incident-id)
  - [Documentation](#documentation)
    - [CAD CLI](#cad-cli)
    - [Investigations](#investigations)
    - [Integrations](#integrations)
    - [Overview](#overview)
    - [Templates](#templates)
    - [Dashboards](#dashboards)
    - [Deployment](#deployment)
    - [Boilerplate](#boilerplate)
    - [PipelinePruner](#pipelinepruner)
    - [Required ENV variables](#required-env-variables)
    - [Optional ENV variables](#optional-env-variables)

# Configuration Anomaly Detection

[![Configuration Anomaly Detection](./images/CadCat.png)](https://github.com/openshift/configuration-anomaly-detection)

## About

Configuration Anomaly Detection (CAD) is responsible for reducing manual SRE effort by pre-investigating alerts, detecting cluster anomalies and sending relevant communications to the cluster owner.

## Contributing 

### Adding a new investigation

CAD investigations are triggered by PagerDuty webhooks. Currently, CAD supports the following two formats of webhooks:
-  WebhookV3 
-  EventOrchestrationWebhook

The required investigation is identified by CAD based on the incident and its payload. 
As PagerDuty itself does not provide finer granularity for webhooks than service-based, CAD filters out the alerts it should investigate. For more information, please refer to https://support.pagerduty.com/docs/webhooks.

To add a new alert investigation:
- create a mapping for the alert to the `getInvestigation` function in `investigate.go` and write a corresponding CAD investigation (e.g. `Investigate()` in `chgm.go`).
- if the alert is not yet routed to CAD, add a webhook to the service your alert fires on. For production, the service should also have an escalation policy that escalates to SRE on CAD automation timeout.

## Testing locally

### Pre-requirements
- an existing cluster
- an existing PagerDuty incident for the cluster and alert type that is being tested

To quickly create an incident for a cluster_id, you can run `./test/generate_incident.sh <alertname> <clusterid>`. 
Example usage:`./test/generate_incident.sh ClusterHasGoneMissing 2b94brrrrrrrrrrrrrrrrrrhkaj`.

### Running cadctl for an incident ID
1) Export the required ENV variables, see [required ENV variables](#required-env-variables).
2) Create a payload file containing the incident ID
  ```bash
  export INCIDENT_ID=
  echo '{"event": {"data":{"id": "${INCIDENT_ID}"}}}' > ./payload
  ```
3) Run `cadctl` using the payload file
  ```bash
  ./cadctl/cadctl investigate --payload-path payload
  ```

## Documentation

### CAD CLI

* [cadctl](./cadctl/README.md) -- Performs investigation workflow.

### Investigations

Every alert managed by CAD corresponds to an investigation, representing the executed code associated with the alert.

Investigation specific documentation can be found in the according investigation folder,  e.g. for [ClusterHasGoneMissing](./pkg/investigations/chgm/README.md).

### Integrations

* [AWS](https://github.com/aws/aws-sdk-go) -- Logging into the cluster, retreiving instance info and AWS CloudTrail events.
* [PagerDuty](https://github.com/PagerDuty/go-pagerduty) -- Retrieving alert info, esclating or silencing incidents, and adding notes. 
* [OCM](https://github.com/openshift-online/ocm-sdk-go) -- Retrieving cluster info, sending service logs, and managing (post, delete) limited support reasons.
* [osd-network-verifier](https://github.com/openshift/osd-network-verifier) -- Tool to verify the pre-configured networking components for ROSA and OSD CCS clusters.

### Overview

- CAD is a command line tool that is run in tekton pipelines. 
- The tekton service is running on an app-sre cluster. 
- CAD is triggered by PagerDuty webhooks configured on selected services, meaning that all alerts in that service trigger a CAD pipeline. 
- CAD uses the data received via the webhook to determine which investigation to start.

![CAD Overview](./images/cad_overview/cad_architecture_dark.png#gh-dark-mode-only)
![CAD Overview](./images/cad_overview/cad_architecture_light.png#gh-light-mode-only)

### Templates

* [Update-Template](./hack/update-template/README.md) -- Updating configuration-anomaly-detection-template.Template.yaml.
* [OpenShift](./openshift/README.md) -- Used by app-interface to deploy the CAD resources on a target cluster.

### Dashboards

Grafana dashboard configmaps are stored in the [Dashboards](./dashboards/) directory. See app-interface for further documentation on dashboards.

### Deployment

* [Tekton](./deploy/README.md) -- Installation/configuration of Tekton and triggering pipeline runs.
* [Skip Webhooks](./deploy/skip-webhook/README.md) -- Skipping the eventlistener and creating the pipelinerun directly.
* [Namespace](./deploy/namespace/README.md) -- Allowing the code to ignore the namespace.

### Boilerplate

* [Boilerplate](./boilerplate/openshift/osd-container-image/README.md) -- Conventions for OSD containers.

### PipelinePruner

* [PipelinePruner](./openshift/PipelinePruning.md) -- Documentation about PipelineRun pruning.

### Required ENV variables

* `CAD_OCM_CLIENT_ID`: refers to the OCM client ID used by CAD to initialize the OCM client
* `CAD_OCM_CLIENT_SECRET`: refers to the OCM client secret used by CAD to initialize the OCM client
* `CAD_OCM_URL`: refers to the used OCM url used by CAD to initialize the OCM client
* `AWS_ACCESS_KEY_ID`: refers to the access key id of the base AWS account used by CAD
* `AWS_SECRET_ACCESS_KEY`: refers to the secret access key of the base AWS account used by CAD
* `CAD_AWS_CSS_JUMPROLE`:  refers to the arn of the RH-SRE-CCS-Access jumprole
* `CAD_AWS_SUPPORT_JUMPROLE`: refers to the arn of the RH-Technical-Support-Access jumprole
* `CAD_ESCALATION_POLICY`:  refers to the escalation policy CAD should use to escalate the incident to
* `CAD_PD_EMAIL`: refers  to the email for a login via mail/pw credentials
* `CAD_PD_PW`: refers to the password for a login via mail/pw credentials
* `CAD_PD_TOKEN`: refers to the generated private access token for token-based authentication
* `CAD_PD_USERNAME`: refers to the username of CAD on PagerDuty
* `CAD_SILENT_POLICY`: refers to the silent policy CAD should use if the incident shall be silent
* `PD_SIGNATURE`: refers to the PagerDuty webhook signature (HMAC+SHA256)
* `X_SECRET_TOKEN`: refers to our custom Secret Token for authenticating against our pipeline
* `CAD_PROMETHEUS_PUSHGATEWAY`: refers to the URL cad will push metrics to
* `BACKPLANE_URL`: refers to the backplane url to use
* `BACKPLANE_INITIAL_ARN`: refers to the initial ARN used for the isolated backplane jumprole flow

### Optional ENV variables

* `BACKPLANE_PROXY`: refers to the proxy CAD uses for the isolated backplane access flow. 

**Note:** `BACKPLANE_PROXY` is required for local development, as a backplane api is only accessible through the proxy.

For Red Hat employees, these environment variables can be found in the SRE-P vault.
