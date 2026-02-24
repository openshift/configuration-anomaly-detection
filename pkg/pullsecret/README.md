# Pull Secret Validation Package

Validates cluster pull secrets against OCM account data.

## Overview

This package is ported from osdctl's `validate-pull-secret-ext` ([command](https://github.com/openshift/osdctl/blob/master/cmd/cluster/validatepullsecretext.go)), adapted for CAD's automated investigation workflow.

## Checks Performed

1. **Email validation**: Compares `cloud.openshift.com` email in cluster pull secret against OCM account email
2. **Registry credentials validation**: For each OCM registry credential, validates email and token match the cluster pull secret

> *Note: osdctl's Access Token validation is not included as it requires Region Lead permissions.*

## Usage

```go
// Email validation
result := pullsecret.ValidateEmail(k8sClient, ocmAccountEmail)

// Registry credentials validation
result, registryResults := pullsecret.ValidateRegistryCredentials(
    k8sClient, ocmConnection, accountID, ocmEmail)

// Check results
for _, warning := range result.Warnings {
    notes.AppendWarning("%s", warning)
}
```
