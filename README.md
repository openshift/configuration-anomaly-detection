# configuration-anomaly-detection
[![Go Report Card](https://goreportcard.com/badge/github.com/openshift/configuration-anomaly-detection)](https://goreportcard.com/report/github.com/openshift/configuration-anomaly-detection) [![PkgGoDev](https://pkg.go.dev/badge/github.com/openshift/configuration-anomaly-detection)](https://pkg.go.dev/github.com/openshift/configuration-anomaly-detection)

## Purpose

configuration-anomaly-detection (CAD) solves the issue of reacting to a cluster's
anomaly and informing the cluster owner of the next steps to do on their behalf.

## Integrations

CAD integrates with multiple third party tools, to read how they work and are developed see [the package folder](./pkg/)

## Install

### cadctl

to install it use the command:

```shell
make cadctl-install-local-force
```

and for more info on the matter see [the cadctl code tree](./cadctl/)

## Contributing

to learn on how to contribute see [our CONTRIBUTING document](./CONTRIBUTING.md)
