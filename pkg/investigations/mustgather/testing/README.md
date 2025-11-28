# Testing mustgather Investigation

This document describes how to test the mustgather investigation end-to-end in a local environment.

## Overview

The mustgather investigation:
1. Collects must-gather diagnostics from a ROSA classic cluster using `oc adm must-gather`
2. Creates a compressed tarball of the output
3. Uploads the tarball to the Red Hat SFTP server using anonymous credentials
4. Posts the upload location to PagerDuty

## Prerequisites

### Environment Requirements
- **Cluster**: ROSA classic cluster (HCP clusters are not supported)
- **Access**: Cluster must be accessible via backplane/OCM
- **Environment Variables**: Set up via `source test/set_stage_env.sh`
- **Local Backplane API**: Start local backplane instance:
  ```bash
  OCM_BACKPLANE_REPO_PATH=<PATH/TO/BACKPLANE>/backplane-api ./test/launch_local_env.sh
  ```

### Build the Binary
```bash
make build
```

## Manual Testing

### Step 1: Create or Identify a ROSA Classic Cluster

You need an actual ROSA classic cluster. Note the cluster ID for the next steps. For a quick test, you can use one of the available CI clusters in staging.

```bash
# List available clusters
ocm login --use-auth-code --url "staging"
ocm list cluster -p search="state is 'ready' AND hypershift.enabled is 'false'" --managed


# Get internal cluster ID from a CI cluster
CLUSTER_ID="<your-cluster-id>"
```

### Step 2: Generate Test Incident Payload

Create a PagerDuty incident payload that triggers the CreateMustGather alert:

```bash
./test/generate_incident.sh CreateMustGather $CLUSTER_ID
```

This creates a `payload` file in the current directory and a PagerDuty incident which can be checked for CAD output.

### Step 3: Set Up Environment

```bash
# Export environment variables from vault
source test/set_stage_env.sh

# Enable experimental investigations
export CAD_EXPERIMENTAL_ENABLED=true
```

### Step 4: Run the Investigation

```bash
BACKPLANE_URL=https://localhost:8443 \
HTTP_PROXY=http://127.0.0.1:8888 \
HTTPS_PROXY=http://127.0.0.1:8888 \
BACKPLANE_PROXY=http://127.0.0.1:8888 \
./bin/cadctl investigate --payload-path ./payload --log-level debug
```

### Step 5: Verify Results

The investigation should:

1. **Collect must-gather** - Check logs for:
   ```
   Running must-gather collection...
   ```

2. **Create tarball** - Look for:
   ```
   Creating tarball from must-gather output...
   Successfully created tarball: /tmp/<timestamp>-must-gather-<cluster-id>.tar.gz
   ```

3. **Fetch SFTP credentials** - Check for:
   ```
   Fetching anonymous SFTP credentials...
   anonymous SFTP username: <generated-username>
   ```

4. **Upload to SFTP** - Look for:
   ```
   Uploading to Red Hat SFTP server...
   Successfully uploaded <bytes> bytes to SFTP server
   ```

5. **Post to PagerDuty** - Verify a note was added to the incident with:
   ```
   CAD collected a must-gather and uploaded it to the Red Hat SFTP server under /anonymous/users/<username>/<tarball-name>
   ```

### Step 6: Verify SFTP Upload (Optional)

You can verify the file was actually uploaded to the Red Hat SFTP server using one of these methods:

**Option 1: Using Anonymous Credentials (from CAD output)**

Use the anonymous username and token that CAD printed during execution:

```bash
# Extract credentials from CAD output
USERNAME="<anonymous-username-from-logs>"
TOKEN="<token-from-sftp-credential-fetch>"

# Connect to SFTP server
sftp -P 22 $USERNAME@sftp.access.redhat.com
# When prompted for password, enter the token

# Once connected, verify the upload
ls /anonymous/users/$USERNAME/
# You should see: <timestamp>-must-gather-<cluster-id>.tar.gz

# Optional: Download to verify integrity
get /anonymous/users/$USERNAME/<timestamp>-must-gather-<cluster-id>.tar.gz

exit
```

**Option 2: Using Red Hat Account (Higher Permissions)**

If you have a Red Hat account, you can login with full permissions:

```bash
# Connect with your RH credentials
sftp <your-rh-username>@sftp.access.redhat.com

# Navigate to the directory posted in the PagerDuty ticket
# The path will be: /anonymous/users/<anonymous-username>/<tarball-name>
ls /anonymous/users/<anonymous-username>/

# You should see the uploaded tarball
# You can also download it for verification
get /anonymous/users/<anonymous-username>/<timestamp>-must-gather-<cluster-id>.tar.gz

exit
```

**Note**: Anonymous credentials are temporary and expire after the time specified in the `expiryDate` field. If you need to access the file later, use your Red Hat account.

## What Gets Collected

A successful must-gather creates the following structure:
```
/tmp/<timestamp>-must-gather-<cluster-id>.tar.gz
└── must-gather.local.XXXXX/
    ├── event-filter.html
    ├── gather-debug.log      (always present - logs the gathering operation)
    ├── timestamp
    └── quay-io-*/            (cluster diagnostic data)
```

The tarball will typically be:
- **Minimum size**: ~100KB (even on empty cluster - contains metadata files)
- **Typical size**: 50MB to several GB (depends on cluster size and activity)
- **Upload speed**: ~10 MB/min to Red Hat SFTP server

## Expected Timeouts

- **Must-gather collection**: No explicit timeout (depends on cluster size, typically 2-10 minutes)
- **SFTP credential fetch**: 30 seconds
- **SFTP upload**: 6 hours (slow server, conservative timeout, expect that to finish within a few minutes for a newly created, mostly "vanilla" cluster)

## Troubleshooting

### Must-Gather Collection Fails

**Symptom**: `oc adm must-gather` command fails

**Possible causes**:
1. Backplane authentication issues
2. Cluster not accessible
3. Insufficient RBAC permissions

**Fix**:
Check the output of cadctl. There may have been changes to required RBAC permissions for a must-gather, or changes to backplane which prevent API access.

### SFTP Credential Fetch Fails

**Symptom**: `failed to get the Red Hat sftp server credentials`

**Possible causes**:
1. Network connectivity issues
2. Red Hat SFTP service unavailable
3. Context timeout (30s exceeded)

**Fix**:
```bash
# Test connectivity
curl -X POST https://access.redhat.com/hydra/rest/v2/sftp/token \
  -H "Content-Type: application/json" \
  -d '{"isAnonymous":true}'
```

### SFTP Upload Fails

**Symptom**: `failed to upload to the Red Hat sftp server`

**Possible causes**:
1. SSH fingerprint mismatch (server certificate changed)
2. Network timeout (upload > 6 hours)
3. SFTP server connection issues
4. Invalid credentials

**Fix**:
```bash
# Check expected fingerprint (from code)
# SHA256:Ij7dPhl1PhiycLC/rFXy1sGO2nSS9ky0PYdYhi+ykpQ

# Verify current server fingerprint
ssh-keyscan -t rsa sftp.access.redhat.com 2>/dev/null | ssh-keygen -lf -
```

### Upload Timeout

**Symptom**: `SFTP upload cancelled: context deadline exceeded`

**Possible causes**:
1. Very large must-gather (> several GB)
2. Slow network connection
3. 6-hour timeout exceeded

**Fix**:
- Check tarball size: `ls -lh /tmp/*must-gather*.tar.gz`
- Consider increasing timeout in `mustgather.go` if needed

## Cleanup

After testing, temporary files are automatically cleaned up via defer statements:
- Must-gather directory: `/tmp/must-gather.cad.*`
- Tarball: `/tmp/<timestamp>-must-gather-<cluster-id>.tar.gz`

If cleanup fails, manually remove:
```bash
rm -rf /tmp/must-gather.cad.*
rm -f /tmp/*-must-gather-*.tar.gz
```
## Notes

- Must-gather is currently **experimental** (`IsExperimental() = true`)
- Only works with **ROSA classic** clusters (not HCP)
- SFTP upload uses **anonymous credentials** (temporary, time-limited)
- Upload location is posted to PagerDuty for SRE access
- The investigation escalates the incident on any failure
