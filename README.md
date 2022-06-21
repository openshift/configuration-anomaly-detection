[![Go Report Card](https://goreportcard.com/badge/github.com/openshift/configuration-anomaly-detection)](https://goreportcard.com/report/github.com/openshift/configuration-anomaly-detection) [![PkgGoDev](https://pkg.go.dev/badge/github.com/openshift/configuration-anomaly-detection)](https://pkg.go.dev/github.com/openshift/configuration-anomaly-detection)

----

- [Configuration Anomaly Detection](#configuration-anomaly-detection)
- [Documentation](#documentation)
  - [CAD CLI](#cad-cli)
  - [Integrations](#integrations)
  - [Workflow](#workflow)
  - [Templates](#templates)
  - [Dashboards](#dashboards)
- [Deployment](#deployment)
- [Boilerplate](#boilerplate)

# Configuration Anomaly Detection

Configuration Anomaly Detection (CAD) is responsible for reducing manual SRE investigation by detecting cluster anomalies and sending relevant communications to the cluster owner.

To contribute to CAD, please see our [CONTRIBUTING Document](CONTRIBUTING.md).

# Documentation

## CAD CLI

* [cadctl](./cadctl/README.md) -- Performs workflow for 'cluster has gone missing' (CHGM) alerts.

## Integrations

* [AWS](./pkg/aws/README.md) -- Logging into the cluster, retreiving instance info and AWS CloudTrail events.
* [PagerDuty](./pkg/pagerduty/README.md) -- Retrieving alert info, esclating or silencing incidents, and adding notes. 
* [OCM](./pkg/ocm/README.md) -- Retrieving cluster info and sending service logs.

## Workflow

TODO - add steps for CAD workflow

## Templates

* [Update-Template](./hack/update-template/README.md) -- Updating configuration-anomaly-detection-template.Template.yaml.
* [OpenShift](./openshift/README.md) -- Used by app-interface to deploy the CAD resources on a target cluster.

## Dashboards

Grafana dashboard configmaps are stored in the [Dashboards](./dashboards/) directory. See app-interface for further documentation on dashboards.

# Deployment

* [Tekton](./deploy/README.md) -- Installation/configuration of Tekton and triggering pipeline runs.
* [Skip Webhooks](./deploy/skip-webhook/README.md) -- Skipping the eventlistener and creating the pipelinerun directly.
* [Namespace](./deploy/namespace/README.md) -- Allowing the code to ignore the namespace.

# Boilerplate

* [Boilerplate](./boilerplate/openshift/osd-container-image/README.md) -- Conventions for OSD containers.
