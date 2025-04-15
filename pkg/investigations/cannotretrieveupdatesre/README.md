# cannotretrieveupdatessre Investigation

Investigates the CannotRetrieveUpdatesSRE alert by running network verifier and posting some cluster version errors.

## Investigation Logic

The `CannotRetrieveUpdatesSRE` investigation is designed to diagnose issues where an OpenShift cluster cannot retrieve updates from its configured channel. It performs two main checks:
1. **Network Verification**: Uses the `networkverifier` package to ensure the cluster can reach required update endpoints.
2. **ClusterVersion Check**: Examines the `ClusterVersion` resource for conditions indicating update retrieval failures, such as `VersionNotFound`.

## Testing

Refer to the [testing README](./testing/README.md) for instructions on testing this investigation
