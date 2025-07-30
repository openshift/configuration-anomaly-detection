# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

Configuration Anomaly Detection (CAD) is a Go-based system that reduces manual SRE effort by pre-investigating alerts, detecting cluster anomalies, and sending relevant communications to cluster owners. It integrates with PagerDuty webhooks and uses Tekton pipelines for automated remediation.

## Development Commands

### Building
- `make build` - Build all subprojects (cadctl and interceptor)
- `make build-cadctl` - Build only the cadctl binary to `./bin/cadctl`
- `make build-interceptor` - Build only the interceptor binary to `./bin/interceptor`

### Testing
- `make test` - Run all tests for both cadctl and interceptor
- `make test-cadctl` - Run unit tests for cadctl and pkg modules
- `make test-interceptor` - Run unit tests for interceptor
- `make test-interceptor-e2e` - Run e2e tests for interceptor

### Linting
- `make lint` - Lint all subprojects
- `make lint-cadctl` - Lint cadctl using golangci-lint
- `make lint-interceptor` - Lint interceptor using golangci-lint

### Code Generation
- `make generate-cadctl` - Generate mocks for cadctl using mockgen

### Local Testing
For testing against clusters:
1. **Create a test cluster** - Manual tests requiring cluster ID need an actual cluster to be created first
2. `./test/generate_incident.sh <alertname> <clusterid>` - Create test incident payload with the cluster ID
3. `source test/set_stage_env.sh` - Export required environment variables from vault
4. `./bin/cadctl investigate --payload-path payload` - Run investigation

**Note**: Tests that require a cluster ID (like manual tests using shell scripts) need you to create a cluster first and provide its ID. Only then can you trigger the PagerDuty alert for that cluster to have local CAD run an investigation on it.

## Architecture

### Core Components

**cadctl** - CLI tool implementing alert investigations and remediations
- Entry point: `cadctl/main.go`
- Commands: `cadctl/cmd/`
- Investigations registry: `pkg/investigations/registry.go`

**interceptor** - Tekton interceptor for webhook filtering
- Entry point: `interceptor/main.go`
- Filters PagerDuty webhooks and validates signatures
- Determines if alerts have implemented handlers

**investigations** - Modular alert investigation implementations
- Location: `pkg/investigations/`
- Each investigation implements the `Investigation` interface
- Investigations include: chgm, ccam, clustermonitoringerrorbudgetburn, etc.

### Investigation Framework

Investigations follow a consistent pattern:
- Implement `Investigation` interface from `pkg/investigations/investigation/investigation.go`
- Include `metadata.yaml` for RBAC permissions
- Testing directory with manual test procedures
- Auto-registered in `pkg/investigations/registry.go`

### Integrations

Pre-initialized clients available in investigation resources:
- **AWS** (`pkg/aws`) - Instance info, CloudTrail events
- **OCM** (`pkg/ocm`) - Cluster info, service logs, limited support reasons
- **PagerDuty** (`pkg/pagerduty`) - Alert info, incident management, notes
- **K8s** (`pkg/k8s`) - Kubernetes API client
- **osd-network-verifier** (`pkg/networkverifier`) - Network verification

### Workflow

1. PagerDuty webhook → Tekton EventListener
2. Interceptor validates and filters webhooks
3. If handler exists → PipelineRun starts
4. Pipeline executes `cadctl investigate`
5. Investigation runs and posts results to PagerDuty

## Adding New Investigations

1. `make bootstrap-investigation` - Generates boilerplate code and directory structure
2. Implement investigation logic in generated files
3. Add test objects/scripts to `testing/` directory
4. Update investigation-specific README with testing procedures
5. Follow progressive deployment: Informing Stage (read-only) → Actioning Stage (read/write)

## Required Environment Variables

For local development (available via `source test/set_stage_env.sh`):
- `CAD_OCM_CLIENT_ID`, `CAD_OCM_CLIENT_SECRET`, `CAD_OCM_URL` - OCM client configuration
- `CAD_PD_EMAIL`, `CAD_PD_PW`, `CAD_PD_TOKEN`, `CAD_PD_USERNAME` - PagerDuty authentication
- `CAD_SILENT_POLICY` - PagerDuty silent policy
- `PD_SIGNATURE` - PagerDuty webhook signature validation
- `BACKPLANE_URL`, `BACKPLANE_INITIAL_ARN` - Backplane access
- `CAD_PROMETHEUS_PUSHGATEWAY` - Metrics endpoint

Optional:
- `BACKPLANE_PROXY` - Required for local development
- `CAD_EXPERIMENTAL_ENABLED=true` - Enable experimental investigations
- `LOG_LEVEL` - Logging level (default: info)