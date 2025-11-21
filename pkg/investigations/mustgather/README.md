# mustgather Investigation

Automated collection and upload of OpenShift must-gather diagnostics for ROSA classic clusters.

## Overview

The mustgather investigation automates the process of collecting cluster diagnostics using `oc adm must-gather` and uploading them to the Red Hat SFTP server. This reduces manual SRE effort when diagnosing cluster issues by providing immediate access to comprehensive diagnostic data.

**Trigger**: PagerDuty alert with title "CreateMustGather"
**Clusters**: ROSA classic only (HCP/Hypershift not supported)
**Status**: Experimental (`IsExperimental() = true`)

## How It Works

The investigation performs the following steps:

1. **Collect diagnostics** - Executes `oc adm must-gather` via backplane connection to gather cluster diagnostic data
2. **Create tarball** - Compresses the must-gather output directory into a `.tar.gz` archive
3. **Fetch SFTP credentials** - Requests temporary anonymous credentials from Red Hat SFTP service
4. **Upload tarball** - Transfers the compressed diagnostics to the Red Hat SFTP server
5. **Post to PagerDuty** - Adds a note to the incident with the SFTP file location

On any failure, the investigation escalates the PagerDuty incident with an error message.

## Architecture

### File Structure

```
pkg/investigations/mustgather/
├── mustgather.go           # Main investigation logic and orchestration
├── sftpUpload.go           # SFTP credential fetching and upload logic
├── sftpUpload_test.go      # Unit tests for HTTP and context-aware IO
├── metadata.yaml           # RBAC permissions for must-gather
├── README.md               # This file
└── testing/
    └── README.md           # Integration testing documentation
```

### Key Components

#### mustgather.go

Main investigation implementation (`Investigation` struct):
- Implements the `investigation.Investigation` interface
- Orchestrates the entire must-gather collection and upload workflow
- Manages temporary directories and cleanup
- Handles context timeouts for different operations


#### sftpUpload.go

SFTP-related functionality:
- `getAnonymousSftpCredentials()` - Fetches temporary anonymous credentials from Red Hat SFTP API
- `sftpUpload()` - Uploads tarball to Red Hat SFTP server with SSH fingerprint validation

**HTTPDoer Interface**: Allows dependency injection for testing HTTP clients

#### utils/tarball

Separate utility package for tarball creation:
- `CreateTarball()` - Creates compressed tar.gz archives from directories
- Handles nested directory structures, permissions, and file metadata
- Located at `pkg/investigations/utils/tarball/`

### RBAC Requirements

The investigation requires an extensive list of RBAC permissions as defined in `metadata.yml`.
CAD will retrieve a REST config from backplane API scoped to the RBAC permissions.
The REST config will be turned into an equivalent kubeconfig file in order to access the cluster API via `oc` as well.

### Context and Timeouts

The investigation uses separate context timeouts for different operations:

| Operation | Timeout | Reason |
|-----------|---------|--------|
| SFTP credential fetch | 30 seconds | Fast HTTP API call |
| SFTP upload | 6 hours | Slow server (~10 MB/min), large files possible |
| Must-gather collection | None | Depends on cluster size (typically 2-10 minutes) |

The SFTP upload uses a custom `copyWithContext()` implementation that checks context cancellation between 32KB chunks, allowing graceful termination of long-running uploads.

### SFTP Upload Details

**Server**: `sftp.access.redhat.com:22`
**Authentication**: Anonymous credentials (temporary, time-limited)
**Upload Path**: `/anonymous/users/<username>/<tarball-name>`
**Fingerprint Validation**: SHA256:Ij7dPhl1PhiycLC/rFXy1sGO2nSS9ky0PYdYhi+ykpQ

The investigation fetches anonymous credentials from the Red Hat SFTP API (https://access.redhat.com/hydra/rest/v2/sftp/token) which provides:
- Temporary username
- Time-limited access token
- Expiration timestamp

See [Red Hat SFTP documentation](https://access.redhat.com/articles/5594481) for more details.

**Note**: The SFTP upload instructions are publicly documented at https://access.redhat.com/articles/5594481, so documenting them here does not constitute a security risk.

## Output

### Tarball Contents

The must-gather tarball contains:
- `event-filter.html` - Event summary visualization
- `gather-debug.log` - Must-gather operation logs
- `timestamp` - Collection timestamp
- `quay-io-*/` - Cluster diagnostic data

**Typical sizes**:
- Minimum: ~100KB (metadata files always present)
- Typical: 50MB to several GB (depends on cluster size)

**Performance**: A 50MB must-gather on a healthy cluster takes approximately 7 minutes end-to-end, with ~5 minutes spent uploading to the SFTP server (due to the slow ~10 MB/min upload speed). Note that must-gathers can be significantly larger depending on cluster size and activity.

### PagerDuty Note

On success, the investigation adds a note to the incident:

```
CAD collected a must-gather and uploaded it to the Red Hat SFTP server under /anonymous/users/<username>/<tarball-name>
```

SREs can download the file from the SFTP server using either:
1. The temporary anonymous credentials (before expiration)
2. Their Red Hat account credentials

## Configuration

The investigation requires no additional configuration beyond standard CAD environment variables. However, it must be explicitly enabled:

```bash
export CAD_EXPERIMENTAL_ENABLED=true
```

## Integration Testing

For end-to-end testing instructions, see [testing/README.md](./testing/README.md).

Integration testing requires:
- A real ROSA classic cluster
- Local backplane API instance
- Access to staging PagerDuty

## Troubleshooting

Common issues and solutions are documented in [testing/README.md](./testing/README.md#troubleshooting).

## Future Enhancements

Potential improvements when graduating from experimental:
- Support for HCP/Hypershift clusters (pending backplane support)
- Configurable upload timeouts
- Parallel uploads for very large files
- Progress reporting during upload
- Automatic retry on transient failures
- Smarter failure handling: Currently, failing must-gathers escalate to primary and post to the channel. Future improvements could track failure metrics, notify the sd-cad channel, and alert only when failures exceed a certain threshold

## Related Documentation

- [Integration Testing Guide](./testing/README.md)
- [Red Hat SFTP Service](https://access.redhat.com/articles/5594481)
- [OpenShift must-gather](https://docs.openshift.com/container-platform/latest/support/gathering-cluster-data.html)
