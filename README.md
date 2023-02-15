[![Go Report Card](https://goreportcard.com/badge/github.com/openshift/configuration-anomaly-detection)](https://goreportcard.com/report/github.com/openshift/configuration-anomaly-detection) [![PkgGoDev](https://pkg.go.dev/badge/github.com/openshift/configuration-anomaly-detection)](https://pkg.go.dev/github.com/openshift/configuration-anomaly-detection)
[![codecov](https://codecov.io/gh/openshift/configure-alertmanager-operator/branch/master/graph/badge.svg)](https://codecov.io/gh/openshift/configuration-anomaly-detection)
[![License](https://img.shields.io/:license-apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)

----

- [Configuration Anomaly Detection](#configuration-anomaly-detection)
  - [About](#about)
  - [Contributing](#contributing)
- [Documentation](#documentation)
  - [CAD CLI](#cad-cli)
  - [Integrations](#integrations)
  - [Overview](#overview)
    - [Alert firing investigation](#alert-firing-investigation)
  - [CHGM investigation overview](#chgm-investigation-overview)
  - [Templates](#templates)
  - [Dashboards](#dashboards)
  - [Deployment](#deployment)
  - [Boilerplate](#boilerplate)
  - [PipelinePruner](#pipelinepruner)

# Configuration Anomaly Detection

[![Configuration Anomaly Detection](./images/CadCat.png)](https://github.com/openshift/configuration-anomaly-detection)

## About

Configuration Anomaly Detection (CAD) is responsible for reducing manual SRE investigation by detecting cluster anomalies and sending relevant communications to the cluster owner.

## Contributing

To contribute to CAD, please see our [CONTRIBUTING Document](CONTRIBUTING.md).

# Documentation

## CAD CLI

* [cadctl](./cadctl/README.md) -- Performs workflow for 'cluster has gone missing' (CHGM) alerts.

## Integrations

* [AWS](./pkg/aws/README.md) -- Logging into the cluster, retreiving instance info and AWS CloudTrail events.
* [PagerDuty](./pkg/pagerduty/README.md) -- Retrieving alert info, esclating or silencing incidents, and adding notes. 
* [OCM](./pkg/ocm/README.md) -- Retrieving cluster info, sending service logs, and managing (post, delete) limited support reasons.

## Overview

- CAD is a command line tool that is run in tekton pipelines. 
- The tekton service is running on an app-sre cluster. 
- CAD is triggered by PagerDuty webhooks configured on selected services, meaning that all alerts in that service trigger a CAD pipeline. 
- CAD uses the data received via the webhook to determine which investigation to start.

![CAD Overview](./images/cad_overview/cad_architecture_dark.png#gh-dark-mode-only)
![CAD Overview](./images/cad_overview/cad_architecture_light.png#gh-light-mode-only)

### Alert firing investigation

1. PagerDuty webhook receives CHGM alert from Dead Man's Snitch.
2. CAD Tekton pipeline is triggered via PagerDuty sending a webhook to Tekton EventListener.
3. Logs into AWS account of cluster and checks for stopped/terminated instances.
    - If unable to access AWS account, posts "cluster credentials are missing" limited support reason.
4. If stopped/terminated instances are found, pulls AWS CloudTrail events for those instances.
    - If no stopped/terminated instances are found, escalates to SRE for further investigation.
5. If the user of the event is:
    - Authorized (SRE or OSD managed), escalates the alert to SRE for futher investigation.
        - **Note:** Authorized users have prefix RH-SRE, osdManagedAdmin, or have the ManagedOpenShift-Installer-Role.
    - Not authorized (not SRE or OSD managed), posts the appropriate limited support reason and silences the alert.
6. Adds notes with investigation details to the PagerDuty alert.


## CHGM investigation overview

![CHGM investigation overview](./images/cad_chgm_investigation/chgm_investigation_dark.png#gh-dark-mode-only)
![CHGM investigation overview](./images/cad_chgm_investigation/chgm_investigation_light.png#gh-light-mode-only)

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
