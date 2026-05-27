# consoleerrorbudgetburn Investigation

Automates the console-ErrorBudgetBurn alert investigation by systematically checking every
layer of the network path: blackbox probes, DNS resolution, VPC egress, load balancer health,
OpenShift router pods, and the console service itself.

The investigation collects diagnostic findings and posts them to PagerDuty. Two checks
(allowedSourceRanges and Route53 DNS) can resolve the alert automatically by sending a
service log and silencing the alert. All other checks are informational -- they collect
context to help SREs triage faster.

## Investigation Flow

The checks run in this order:

| # | Check | Scope | Type |
|---|-------|-------|------|
| 1 | **Blackbox probe analysis** -- execs into blackbox-exporter, classifies failure mode (dns/timeout/tls/connection_refused/server_error) | All clusters | Informational |
| 2 | **AllowedSourceRanges** -- detects if the IngressController's allowedSourceRanges excludes the machine CIDR | Classic only | Actioning -- sends service log + silences |
| 3 | **Upstream DNS** -- detects customer-configured upstreamResolvers in dns.operator.openshift.io | All clusters | Informational |
| 4 | **Router pod health** -- checks pod status, restarts, readiness, and warning events in openshift-ingress | All clusters | Informational |
| 5 | **Console service** -- execs into cluster-monitoring-operator pod, curls the console service, reports HTTP response | All clusters | Informational |
| 6 | **Console pod health** -- checks pod status, restarts, readiness, and warning events in openshift-console | All clusters | Informational |
| 7 | **Node health** -- checks node conditions (NotReady, DiskPressure, MemoryPressure) for nodes running console pods | All clusters | Informational |
| 8 | **Route53 DNS** -- verifies *.apps records exist in private and public hosted zones | AWS only (classic + HCP) | Actioning -- sends service log + silences |
| 9 | **DHCP option set** -- verifies the VPC's DHCP option set includes AmazonProvidedDNS | AWS classic only | Informational |
| 10 | **Load balancer health** -- identifies CLB/NLB type, checks target health | AWS classic only | Informational |
| 11 | **VPC egress** -- runs the osd-network-verifier to test outbound connectivity | AWS classic, public only | Informational |

If no automated root cause is found, the investigation escalates to SRE with all collected findings.

## Architecture

The investigation uses a multi-phase resource Build pattern:

1. **Phase 1 (K8s)**: `rb.WithCluster().WithK8sClient().Build()` -- runs all K8s-based checks (1-7).
2. **Phase 2 (AWS)**: `rb.WithAwsClient().Build()` -- runs AWS-specific checks (8-10). Graceful degradation if the AWS client cannot be initialized.
3. **Phase 3 (Egress)**: `rb.WithClusterDeployment().Build()` -- fetches the ClusterDeployment for the network verifier (check 11). Only for public classic clusters.

Interface-based dependency injection is used for three operations that require pod exec or external calls:
- `consoleServiceChecker` -- curling the console service from within the cluster
- `blackboxProber` -- running the blackbox probe via exec into blackbox-exporter
- `egressVerifier` -- wrapping the network verifier (launches a temporary EC2 instance)

## SOP Reference

- Classic: [console-ErrorBudgetBurn.md](../../../../ops-sop/v4/alerts/console-ErrorBudgetBurn.md)
- HCP: [console-ErrorBudgetBurn.md](../../../../ops-sop/v4/alerts/hypershift/console-ErrorBudgetBurn.md)
