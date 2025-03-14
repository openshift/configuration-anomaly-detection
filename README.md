[![Go Report Card](https://goreportcard.com/badge/github.com/openshift/configuration-anomaly-detection)](https://goreportcard.com/report/github.com/openshift/configuration-anomaly-detection) [![PkgGoDev](https://pkg.go.dev/badge/github.com/openshift/configuration-anomaly-detection)](https://pkg.go.dev/github.com/openshift/configuration-anomaly-detection)
[![codecov](https://codecov.io/gh/openshift/configuration-anomaly-detection/branch/main/graph/badge.svg)](https://codecov.io/gh/openshift/configuration-anomaly-detection)
[![License](https://img.shields.io/:license-apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)

----

- [Configuration Anomaly Detection](#configuration-anomaly-detection)
  - [About](#about)
  - [Overview](#overview)
    - [Workflow](#workflow)
  - [Contributing](#contributing)
    - [Building](#building)
    - [Adding a new investigation](#adding-a-new-investigation)
  - [Testing locally](#testing-locally)
    - [Pre-requirements](#pre-requirements)
    - [Running cadctl for an incident ID](#running-cadctl-for-an-incident-id)
  - [Documentation](#documentation)
    - [Investigations](#investigations)
    - [Integrations](#integrations)
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

## Overview

CAD consists of:
- a tekton deployment including a custom tekton interceptor
- the `cadctl` command line tool implementing alert remediations and pre-investigations

### Workflow

1) [PagerDuty Webhooks](https://support.pagerduty.com/docs/webhooks) are used to trigger Configuration-Anomaly-Detection when a [PagerDuty incident](https://support.pagerduty.com/docs/incidents) is created
2) The webhook routes to a [Tekton EventListener](https://tekton.dev/docs/triggers/eventlisteners/)
3) Received webhooks are filtered by a [Tekton Interceptor](https://tekton.dev/docs/triggers/interceptors/) that uses the payload to evaluate whether the alert has an implemented handler function in `cadctl` or not, and validates the webhook against the `X-PagerDuty-Signature` header. If there is no handler implemented, the alert is directly forwarded to a human SRE.
4) If `cadctl` implements a handler for the received payload/alert, a [Tekton PipelineRun](https://tekton.dev/docs/pipelines/pipelineruns/) is started.
5) The pipeline runs `cadctl` which determines the handler function by itself based on the payload.

![CAD Overview](./images/cad_overview/cad_architecture_dark.png#gh-dark-mode-only)
![CAD Overview](./images/cad_overview/cad_architecture_light.png#gh-light-mode-only)

## Contributing

### Building

For build targets, see `make help`.

### Adding a new investigation

CAD investigations are triggered by PagerDuty webhooks. Currently, CAD supports the following two formats of webhooks:
-  WebhookV3
-  EventOrchestrationWebhook

The required investigation is identified by CAD based on the incident and its payload.
As PagerDuty itself does not provide finer granularity for webhooks than service-based, CAD filters out the alerts it should investigate. For more information, please refer to https://support.pagerduty.com/docs/webhooks.

To add a new alert investigation:

- run `make bootstrap-investigation` to generate boilerplate code in `pkg/investigations` (This creates the corresponding folder & .go file, and also appends the investigation to the `availableInvestigations` interface in `registry.go`.).
- investigation.Resources contain initialized clients for the clusters aws environment, ocm and more. See [Integrations](#integrations)

### Integrations

> **Note:** When writing an investiation, you can use them right away.
They are initialized for you and passed to the investigation via investigation.Resources.


* [AWS](https://github.com/aws/aws-sdk-go) -- Logging into the cluster, retreiving instance info and AWS CloudTrail events.
    - See `pkg/aws`
* [PagerDuty](https://github.com/PagerDuty/go-pagerduty) -- Retrieving alert info, esclating or silencing incidents, and adding notes.
    - See `pkg/pagerduty`
* [OCM](https://github.com/openshift-online/ocm-sdk-go) -- Retrieving cluster info, sending service logs, and managing (post, delete) limited support reasons.
    - See `pkg/ocm`
    - In case of missing permissions to query an ocm resource, add it to the Configuration-Anomaly-Detection role in uhc-account-manager
* [osd-network-verifier](https://github.com/openshift/osd-network-verifier) -- Tool to verify the pre-configured networking components for ROSA and OSD CCS clusters.
* [k8sclient](https://pkg.go.dev/sigs.k8s.io/controller-runtime/pkg/client) -- Interact with clusters kube-api
    - Requires RBAC definitions for your investigation to be added to `metadata.yaml`

## Testing locally

### Pre-requirements
- An existing stage cluster
- A Pagerduty incident

```bash
# (Optional) Export you pagerduty token to automatically retireve the incident id
export pd_token=<your_pd_token>
# Generates incident and creates payload file with incident ID
./test/generate_incident.sh <alertname> <clusterid>
```

If you are not using pd_token, create the payload file with the incidentID manually
  ```bash
  export INCIDENT_ID=
  echo '{"__pd_metadata":{"incident":{"id":"'${INCIDENT_ID}'"}}}' > ./payload
  ```

### Running cadctl

1) Run backplane-api locally in a second terminal ( requires being logged into ocm )

    ```
    ./test/backplane.sh
    ```

    > If there is an issue with this step, comment out the `BACKPLANE_URL` env in `set_stage_env.sh`. You will then run against stage backplane, meaning backplane wont be able to see any local changes to metadata files, expect errors like `file not found`
2) Export the required ENV variables, see [required ENV variables](#required-env-variables).
    ```
    source test/set_stage_env.sh
    ```
3) Run `cadctl` using the payload file
    ```bash
    ./bin/cadctl investigate --payload-path payload
    ```

    > If you are testing a new invesitigation using k8sclient, you need to run backplane locally and the metadata file needs to be temporarily commited to main.

### Logging levels

CAD allows for different logging levels (debug, info, warn, error, fatal, panic). The log level is determind through a hierarchy, where the cli flag `log-level`
is checked first, and if not set the optional environment variable `LOG_LEVEL` is used. If neither is set, the log level defaults to `info`.

## Documentation

### Investigations

Every alert managed by CAD corresponds to an investigation, representing the executed code associated with the alert.

Investigation specific documentation can be found in the according investigation folder,  e.g. for [ClusterHasGoneMissing](./pkg/investigations/chgm/README.md).

### Integrations

* [AWS](https://github.com/aws/aws-sdk-go) -- Logging into the cluster, retreiving instance info and AWS CloudTrail events.
* [PagerDuty](https://github.com/PagerDuty/go-pagerduty) -- Retrieving alert info, esclating or silencing incidents, and adding notes.
* [OCM](https://github.com/openshift-online/ocm-sdk-go) -- Retrieving cluster info, sending service logs, and managing (post, delete) limited support reasons.
* [osd-network-verifier](https://github.com/openshift/osd-network-verifier) -- Tool to verify the pre-configured networking components for ROSA and OSD CCS clusters.

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

**Note:** For local execution, these can exported from vault with `source test/set_stage_env.sh`

* `CAD_OCM_CLIENT_ID`: refers to the OCM client ID used by CAD to initialize the OCM client
* `CAD_OCM_CLIENT_SECRET`: refers to the OCM client secret used by CAD to initialize the OCM client
* `CAD_OCM_URL`: refers to the used OCM url used by CAD to initialize the OCM client
* `AWS_ACCESS_KEY_ID`: refers to the access key id of the base AWS account used by CAD
* `AWS_SECRET_ACCESS_KEY`: refers to the secret access key of the base AWS account used by CAD
* `CAD_AWS_CSS_JUMPROLE`:  refers to the arn of the RH-SRE-CCS-Access jumprole
* `CAD_AWS_SUPPORT_JUMPROLE`: refers to the arn of the RH-Technical-Support-Access jumprole
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

- `BACKPLANE_PROXY`: refers to the proxy CAD uses for the isolated backplane access flow.

**Note:** `BACKPLANE_PROXY` is required for local development, as a backplane api is only accessible through the proxy.

- `CAD_EXPERIMENTAL_ENABLED`: enables experimental investigations when set to `true`, see mapping.go

For Red Hat employees, these environment variables can be found in the SRE-P vault.

- `LOG_LEVEL`: refers to the CAD log level, if not set, the default is `info`. See
