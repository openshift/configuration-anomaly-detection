[![Go Report Card](https://goreportcard.com/badge/github.com/openshift/configuration-anomaly-detection)](https://goreportcard.com/report/github.com/openshift/configuration-anomaly-detection) [![PkgGoDev](https://pkg.go.dev/badge/github.com/openshift/configuration-anomaly-detection)](https://pkg.go.dev/github.com/openshift/configuration-anomaly-detection)
[![codecov](https://codecov.io/gh/openshift/configuration-anomaly-detection/branch/main/graph/badge.svg)](https://codecov.io/gh/openshift/configuration-anomaly-detection)
[![License](https://img.shields.io/:license-apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)

----

- [Configuration Anomaly Detection](#configuration-anomaly-detection)
  - [About](#about)
  - [Contributing](#contributing)
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

# Configuration Anomaly Detection

[![Configuration Anomaly Detection](./images/CadCat.png)](https://github.com/openshift/configuration-anomaly-detection)

## About

Configuration Anomaly Detection (CAD) is responsible for reducing manual SRE effort by pre-investigating alerts, detecting cluster anomalies and sending relevant communications to the cluster owner.

## Contributing

To contribute to CAD, please see our [CONTRIBUTING Document](CONTRIBUTING.md).

# Documentation

## CAD CLI

* [cadctl](./cadctl/README.md) -- Performs investigation workflow.

## Investigations

Every alert managed by CAD corresponds to an investigation, representing the executed code associated with the alert.

Investigation specific documentation can be found in the according investigation folder,  e.g. for [ClusterHasGoneMissing](./pkg/investigations/chgm/README.md).

## Integrations

* [AWS](https://github.com/aws/aws-sdk-go) -- Logging into the cluster, retreiving instance info and AWS CloudTrail events.
* [PagerDuty](https://github.com/PagerDuty/go-pagerduty) -- Retrieving alert info, esclating or silencing incidents, and adding notes. 
* [OCM](https://github.com/openshift-online/ocm-sdk-go) -- Retrieving cluster info, sending service logs, and managing (post, delete) limited support reasons.
* [osd-network-verifier](https://github.com/openshift/osd-network-verifier) -- Tool to verify the pre-configured networking components for ROSA and OSD CCS clusters.

## Overview

- CAD is a command line tool that is run in tekton pipelines. 
- The tekton service is running on an app-sre cluster. 
- CAD is triggered by PagerDuty webhooks configured on selected services, meaning that all alerts in that service trigger a CAD pipeline. 
- CAD uses the data received via the webhook to determine which investigation to start.

![CAD Overview](./images/cad_overview/cad_architecture_dark.png#gh-dark-mode-only)
![CAD Overview](./images/cad_overview/cad_architecture_light.png#gh-light-mode-only)

## Templates

* [Update-Template](./hack/update-template/README.md) -- Updating configuration-anomaly-detection-template.Template.yaml.
* [OpenShift](./openshift/README.md) -- Used by app-interface to deploy the CAD resources on a target cluster.

## Dashboards

Grafana dashboard configmaps are stored in the [Dashboards](./dashboards/) directory. See app-interface for further documentation on dashboards.

## Deployment

* [Tekton](./deploy/README.md) -- Installation/configuration of Tekton and triggering pipeline runs.
* [Skip Webhooks](./deploy/skip-webhook/README.md) -- Skipping the eventlistener and creating the pipelinerun directly.
* [Namespace](./deploy/namespace/README.md) -- Allowing the code to ignore the namespace.

## Boilerplate

* [Boilerplate](./boilerplate/openshift/osd-container-image/README.md) -- Conventions for OSD containers.

## PipelinePruner

* [PipelinePruner](./openshift/PipelinePruning.md) -- Documentation about PipelineRun pruning.

## Required ENV variables

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

For Red Hat employees, these environment variables can be found in the SRE-P vault.
