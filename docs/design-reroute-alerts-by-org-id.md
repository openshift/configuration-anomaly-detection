# Design Document: Reroute PagerDuty Alerts Based on Organization ID

**Status:** Proposed  


## Table of Contents

1. [Overview](#overview)
2. [Problem Statement](#problem-statement)
3. [Goals](#goals)
4. [Non-Goals](#non-goals)
5. [Background](#background)
6. [Proposed Solutions](#proposed-solutions)
7. [Detailed Design](#detailed-design)
8. [Alternatives Considered](#alternatives-considered)


---

## Overview

This document proposes a mechanism to route PagerDuty alerts to dedicated escalation policies based on the cluster's organization ID. This enables differentiated support tiers, custom SLAs, and specialized escalation paths for different customer organizations.

## Problem Statement

Currently, all PagerDuty alerts in the Configuration Anomaly Detection (CAD) system follow a uniform escalation path regardless of the customer organization. This creates several challenges:

1. **No differentiation for premium customers** - High-value customers receive the same escalation path as standard customers
2. **Inability to honor custom SLAs** - Some organizations have contractual SLA requirements that differ from standard support
3. **Lack of specialized routing** - Certain organizations may require specialized teams or escalation procedures
4. **Manual intervention required** - SREs must manually re-route alerts for special cases, increasing response time

### Example Scenarios

- **Premium Support Tier**: Organization "ACME-Corp" (org-id: `1a2b3c4d`) pays for premium support and requires immediate escalation to senior SREs
- **Managed Services**: Organization "TechStartup" (org-id: `5e6f7g8h`) has a dedicated managed services team
- **Regional Requirements**: Organization "EuroBank" (org-id: `9i0j1k2l`) requires escalation to EU-based on-call teams for compliance reasons

## Goals

1. **Automated routing** - Automatically route alerts to the correct escalation policy based on organization ID
2. **Configurable mappings** - Allow easy configuration of org-id to escalation-policy mappings without code changes
3. **Backward compatibility** - Maintain current behavior for organizations without special routing requirements
4. **Observable** - Provide metrics and logging for routing decisions
5. **Low latency** - Routing should add minimal delay to alert processing (<1 second)

## Non-Goals

1. Dynamic escalation policy creation - We assume escalation policies are pre-configured in PagerDuty
2. Organization-based investigation logic - This only affects routing, not investigation behavior
3. Multi-organization alerts - Alerts always belong to a single cluster/organization

## Background

### Current Architecture

```
┌─────────────────┐
│ PagerDuty       │
│ Webhook         │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Tekton          │
│ EventListener   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ CAD Interceptor │  ← Validates signature, checks if investigation exists
│ (pdinterceptor) │     Routes to Silent Policy or Escalates to SRE
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Tekton Pipeline │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ cadctl          │  ← Runs investigation, posts results
│ investigate     │
└─────────────────┘
```

### Key Components

1. **Interceptor** (`interceptor/pkg/interceptor/pdinterceptor.go`)
   - Validates PagerDuty webhook signatures
   - Determines if alert has a registered investigation
   - Returns `Continue: true/false` to Tekton

2. **PagerDuty Client** (`pkg/pagerduty/pagerduty.go`)
   - `RetrieveClusterID()` - Extracts cluster ID from alert
   - `moveToEscalationPolicy(policyID)` - Moves incident to specified escalation policy
   - `EscalateIncident()` - Escalates to level 2 (current + 1)

3. **OCM Client** (`pkg/ocm/ocm.go`)
   - `GetClusterInfo(clusterID)` - Retrieves cluster details from OCM
   - Cluster object contains `Organization()` method with `ID()` and `Name()`

### Current Escalation Behavior

```go
// interceptor/pkg/interceptor/pdinterceptor.go:158
if investigation == nil {
    err = pdClient.EscalateIncidentWithNote("🤖 No automation implemented...")
    return &triggersv1.InterceptorResponse{Continue: false}
}
```

Alerts without registered investigations are escalated to the default escalation policy (level 2).

## Proposed Solutions

We propose three approaches, with **Approach 1** as the recommended solution.

### Approach 1: PagerDuty Event Orchestration (Recommended)

**Route alerts using PagerDuty's built-in Event Orchestration** before they reach CAD.

#### Pros
- ✅ No code changes to CAD required
- ✅ Routing happens at PagerDuty layer (fastest)
- ✅ Easy to modify via PagerDuty UI
- ✅ Leverages PagerDuty's native capabilities
- ✅ No additional API calls required
- ✅ Works even if CAD is down

#### Cons
- ❌ Requires alerting system to include org_id in payload
- ❌ Configuration lives in PagerDuty (less visibility in git)
- ❌ Requires PagerDuty admin access to modify rules

### Approach 2: Interceptor-Based Routing

**Modify the CAD interceptor to query OCM and route based on organization ID.**

#### Pros
- ✅ Configuration in code (version controlled)
- ✅ Full control over routing logic
- ✅ Can implement complex routing rules
- ✅ Metrics and logging in CAD system

#### Cons
- ❌ Adds latency (OCM API call per alert)
- ❌ Increases interceptor complexity
- ❌ Requires OCM credentials in interceptor
- ❌ If interceptor fails, no routing occurs

### Approach 3: Investigation-Time Routing

**Route alerts during the investigation phase after cluster info is already retrieved.**

#### Pros
- ✅ Minimal changes to existing code
- ✅ Cluster info already available
- ✅ Can make routing decisions based on investigation results

#### Cons
- ❌ Routing happens late (after investigation starts)
- ❌ Delay in notifying correct team
- ❌ Wastes resources if alert doesn't need investigation

---

## Detailed Design

### Recommended Approach: PagerDuty Event Orchestration

#### Architecture

```
┌──────────────────────┐
│ Prometheus           │
│ Alertmanager         │
│                      │
│ Add org_id label ────┼─────┐
└──────────────────────┘     │
                              │
                              ▼
┌──────────────────────────────────────────────┐
│ PagerDuty Event Orchestration                │
│                                              │
│ Rule 1: org_id = "premium-org-123"          │
│   → Route to "Premium Customer EP"          │
│                                              │
│ Rule 2: org_id = "managed-org-456"          │
│   → Route to "Managed Services EP"          │
│                                              │
│ Rule 3: org_id matches "^regulated-.*"      │
│   → Route to "Compliance Team EP"           │
│                                              │
│ Default: Route to "Standard SRE EP"         │
└──────────┬───────────────────────────────────┘
           │
           ▼
┌──────────────────────┐
│ Escalation Policy    │
│ (Organization-       │
│  specific)           │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ CAD Webhook          │
│ (continues normal    │
│  investigation flow) │
└──────────────────────┘
```

#### Implementation Steps

##### Step 1: Add Organization ID to Alert Payload

**1.1 Update Prometheus Recording Rules**

Create a recording rule to join cluster_id with organization_id:

```yaml
# prometheus-rules.yaml
groups:
  - name: cluster_metadata
    interval: 5m
    rules:
      - record: cluster:organization:info
        expr: |
          label_replace(
            label_join(
              kube_namespace_labels{label_api_openshift_com_id!=""},
              "cluster_id", "", "label_api_openshift_com_id"
            ),
            "org_id", "$1", "label_api_openshift_com_organization", "(.*)"
          )
```

**1.2 Add org_id Label to Alerting Rules**

Update existing alert rules to include organization metadata:

```yaml
# alerting-rules.yaml
groups:
  - name: cluster_alerts
    rules:
      - alert: ClusterHealthCheckFailure
        expr: |
          cluster_health_status == 0
        labels:
          severity: critical
          cluster_id: "{{ $labels.cluster_id }}"
          org_id: "{{ $labels.org_id }}"  # ← Add this
        annotations:
          summary: "Cluster {{ $labels.cluster_id }} health check failed"
```

**1.3 Configure Alertmanager to Pass org_id**

```yaml
# alertmanager.yaml
receivers:
  - name: pagerduty-cad
    pagerduty_configs:
      - service_key: $PAGERDUTY_INTEGRATION_KEY
        details:
          cluster_id: '{{ .GroupLabels.cluster_id }}'
          org_id: '{{ .GroupLabels.org_id }}'  # ← Add this
          alert_name: '{{ .GroupLabels.alertname }}'
```

**1.4 Verify Payload Structure**

The resulting PagerDuty event payload should look like:

```json
{
  "routing_key": "...",
  "event_action": "trigger",
  "payload": {
    "summary": "ClusterHealthCheckFailure CRITICAL",
    "source": "prometheus",
    "severity": "critical",
    "custom_details": {
      "cluster_id": "1a2b3c4d5e6f",
      "org_id": "premium-org-123",  // ← Organization ID
      "alert_name": "ClusterHealthCheckFailure"
    }
  }
}
```

##### Step 2: Configure PagerDuty Event Orchestration

**2.1 Create Organization-Specific Escalation Policies**

In PagerDuty UI:

1. Navigate to **People** → **Escalation Policies**
2. Create policies for each organization tier:
   - `Premium Customers - Priority EP`
   - `Managed Services - Dedicated Team EP`
   - `Regulated Industries - Compliance Team EP`
   - `Standard Support EP` (default)

**2.2 Configure Event Orchestration Rules**

Navigate to **Automation** → **Event Orchestration** → Create new orchestration:

```yaml
# Event Orchestration Configuration (YAML representation)
name: "CAD Alert Routing by Organization"
team: "SRE Platform"

rules:
  # Rule 1: Premium Organizations
  - label: "Premium Customer Routing"
    conditions:
      - path: "custom_details.org_id"
        operator: "matches"
        value: "^(premium-org-.*|vip-org-.*)$"
    actions:
      - route_to: "Premium Customers - Priority EP"
      - annotate:
          note: "Routed to premium support (org_id: {{custom_details.org_id}})"
      - priority: "P1"

  # Rule 2: Managed Services Organizations  
  - label: "Managed Services Routing"
    conditions:
      - path: "custom_details.org_id"
        operator: "equals"
        value: "managed-org-456"
    actions:
      - route_to: "Managed Services - Dedicated Team EP"
      - annotate:
          note: "Routed to managed services team"
      - add_tag: "managed-services"

  # Rule 3: Regulated Industries
  - label: "Compliance-Required Organizations"
    conditions:
      - path: "custom_details.org_id"
        operator: "matches"
        value: "^regulated-.*$"
    actions:
      - route_to: "Regulated Industries - Compliance Team EP"
      - annotate:
          note: "Routed to compliance team (org_id: {{custom_details.org_id}})"
      - add_tag: "compliance"

  # Rule 4: Regional Routing (EU)
  - label: "EU Organizations"
    conditions:
      - path: "custom_details.org_id"
        operator: "matches"
        value: "^eu-.*$"
    actions:
      - route_to: "EU On-Call Team EP"
      - annotate:
          note: "Routed to EU team for GDPR compliance"
      - add_tag: "eu-region"

  # Default Rule
  - label: "Default Routing"
    conditions: []  # Catch-all
    actions:
      - route_to: "Standard Support EP"
      - annotate:
          note: "Standard routing (org_id: {{custom_details.org_id}})"
```

**2.3 Update Webhook Configuration**

Ensure the PagerDuty service's webhook points to CAD's event listener:

```
Service: configuration-anomaly-detection
Webhook URL: https://tekton-listener.cad.svc.cluster.local/
Webhook Events: 
  - incident.triggered
  - incident.resolved
```

##### Step 3: Configuration Management

**3.1 Create Organization Mapping ConfigMap**

For documentation and reference, maintain a ConfigMap:

```yaml
# config/org-escalation-mapping.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: cad-org-escalation-mapping
  namespace: configuration-anomaly-detection
data:
  mappings.yaml: |
    # Organization ID to Escalation Policy Mapping
    # This is documentation only - actual routing configured in PagerDuty Event Orchestration
    
    organizations:
      # Premium Tier
      - org_id: "premium-org-123"
        org_name: "ACME Corporation"
        escalation_policy: "Premium Customers - Priority EP"
        escalation_policy_id: "PABCDEF"
        sla_response_time: "15m"
        notes: "24/7 premium support, direct escalation to senior SREs"
        
      - org_id: "vip-org-789"
        org_name: "Global Tech Inc"
        escalation_policy: "Premium Customers - Priority EP"
        escalation_policy_id: "PABCDEF"
        sla_response_time: "15m"
        
      # Managed Services
      - org_id: "managed-org-456"
        org_name: "TechStartup"
        escalation_policy: "Managed Services - Dedicated Team EP"
        escalation_policy_id: "PGHIJKL"
        sla_response_time: "30m"
        notes: "Dedicated managed services team handles all issues"
        
      # Regulated Industries
      - org_id: "regulated-bank-001"
        org_name: "EuroBank"
        escalation_policy: "Regulated Industries - Compliance Team EP"
        escalation_policy_id: "PMNOPQR"
        sla_response_time: "30m"
        notes: "GDPR compliance required, EU-based team only"
        
    # Default escalation
    default:
      escalation_policy: "Standard Support EP"
      escalation_policy_id: "PSTUVWX"
      sla_response_time: "1h"
```

**3.2 Create Sync Script**

Create a script to validate PagerDuty configuration matches the ConfigMap:

```bash
#!/bin/bash
# scripts/verify-org-routing.sh

set -e

PAGERDUTY_API_TOKEN=${PAGERDUTY_API_TOKEN:?Required}
CONFIG_FILE="config/org-escalation-mapping.yaml"

echo "Verifying PagerDuty event orchestration configuration..."

# Extract org IDs from ConfigMap
ORG_IDS=$(yq eval '.data."mappings.yaml" | .organizations[].org_id' $CONFIG_FILE)

# Verify each escalation policy exists in PagerDuty
for org_id in $ORG_IDS; do
  policy_id=$(yq eval ".data.\"mappings.yaml\" | .organizations[] | select(.org_id == \"$org_id\") | .escalation_policy_id" $CONFIG_FILE)
  
  echo "Checking policy $policy_id for org $org_id..."
  
  response=$(curl -s -H "Authorization: Token token=$PAGERDUTY_API_TOKEN" \
    "https://api.pagerduty.com/escalation_policies/$policy_id")
  
  if echo "$response" | jq -e '.escalation_policy' > /dev/null; then
    echo "✓ Policy $policy_id exists"
  else
    echo "✗ Policy $policy_id not found!"
    exit 1
  fi
done

echo "All escalation policies verified successfully"
```

##### Step 4: Monitoring and Observability

**4.1 Add PagerDuty Routing Metrics**

Create a Grafana dashboard to monitor routing decisions:

```yaml
# dashboards/org-routing-dashboard.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: cad-org-routing-dashboard
  namespace: configuration-anomaly-detection
data:
  dashboard.json: |
    {
      "title": "CAD Alert Routing by Organization",
      "panels": [
        {
          "title": "Alerts Routed by Organization",
          "targets": [
            {
              "expr": "sum by (org_id) (pagerduty_incidents_routed_total)",
              "legendFormat": "{{ org_id }}"
            }
          ]
        },
        {
          "title": "Alerts by Escalation Policy",
          "targets": [
            {
              "expr": "sum by (escalation_policy) (pagerduty_incidents_total)",
              "legendFormat": "{{ escalation_policy }}"
            }
          ]
        },
        {
          "title": "Routing Decision Time",
          "targets": [
            {
              "expr": "histogram_quantile(0.95, pagerduty_routing_duration_seconds)",
              "legendFormat": "p95"
            }
          ]
        }
      ]
    }
```

**4.2 Add Logging**

Enhance CAD interceptor to log organization information:

```go
// interceptor/pkg/interceptor/pdinterceptor.go
func (pdi *interceptorHandler) process(ctx context.Context, r *triggersv1.InterceptorRequest) *triggersv1.InterceptorResponse {
    pdClient, err := pagerduty.GetPDClient([]byte(r.Body))
    if err != nil {
        return interceptors.Failf(codes.InvalidArgument, "could not initialize pagerduty client: %v", err)
    }

    // Log organization ID if present in alert details
    clusterID, err := pdClient.RetrieveClusterID()
    if err == nil {
        logging.Infof("Processing alert for cluster %s", clusterID)
        // Note: org_id will be in the PagerDuty incident custom_details
        // This is for debugging - actual routing happens in PagerDuty
    }

    // ... rest of existing logic
}
```

### Alternative: Interceptor-Based Routing (Backup Approach)

If PagerDuty Event Orchestration is not feasible, implement routing in the interceptor.

#### Implementation

**1. Update Interceptor Environment Variables**

```yaml
# openshift/template.yaml
- name: CAD_ORG_ROUTING_ENABLED
  value: "true"
- name: CAD_ORG_ROUTING_CONFIG
  valueFrom:
    configMapKeyRef:
      name: cad-org-routing-config
      key: routing.yaml
```

**2. Create Routing Configuration**

```yaml
# config/org-routing-config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: cad-org-routing-config
  namespace: configuration-anomaly-detection
data:
  routing.yaml: |
    enabled: true
    cache_ttl: 3600  # Cache org-to-policy mapping for 1 hour
    
    mappings:
      premium-org-123: PABCDEF  # Escalation Policy ID
      managed-org-456: PGHIJKL
      regulated-bank-001: PMNOPQR
      
    patterns:
      - regex: "^premium-org-.*"
        policy_id: PABCDEF
      - regex: "^regulated-.*"
        policy_id: PMNOPQR
        
    default_policy_id: PSTUVWX
```

**3. Modify Interceptor Code**

```go
// interceptor/pkg/interceptor/pdinterceptor.go

type orgRouter struct {
    ocmClient    *ocm.SdkClient
    config       *routingConfig
    cache        *orgCache
}

type routingConfig struct {
    Enabled          bool                `yaml:"enabled"`
    CacheTTL         int                 `yaml:"cache_ttl"`
    Mappings         map[string]string   `yaml:"mappings"`
    Patterns         []patternMapping    `yaml:"patterns"`
    DefaultPolicyID  string              `yaml:"default_policy_id"`
}

type patternMapping struct {
    Regex    string `yaml:"regex"`
    PolicyID string `yaml:"policy_id"`
}

func (pdi *interceptorHandler) process(ctx context.Context, r *triggersv1.InterceptorRequest) *triggersv1.InterceptorResponse {
    pdClient, err := pagerduty.GetPDClient([]byte(r.Body))
    if err != nil {
        return interceptors.Failf(codes.InvalidArgument, "could not initialize pagerduty client: %v", err)
    }

    // Check if org-based routing is enabled
    orgRoutingEnabled, _ := strconv.ParseBool(os.Getenv("CAD_ORG_ROUTING_ENABLED"))
    
    if orgRoutingEnabled {
        if err := pdi.routeByOrganization(ctx, pdClient); err != nil {
            logging.Errorf("Failed to route by organization: %v", err)
            // Continue with standard flow on error
        }
    }

    experimentalEnabledVar := os.Getenv("CAD_EXPERIMENTAL_ENABLED")
    cadExperimentalEnabled, _ := strconv.ParseBool(experimentalEnabledVar)

    investigation := investigations.GetInvestigation(pdClient.GetTitle(), cadExperimentalEnabled)
    if investigation == nil {
        logging.Infof("Incident %s is not mapped to an investigation, escalating incident", pdClient.GetIncidentID())
        err = pdClient.EscalateIncidentWithNote("🤖 No automation implemented for this alert; escalated to SRE. 🤖")
        if err != nil {
            logging.Errorf("failed to escalate incident '%s': %w", pdClient.GetIncidentID(), err)
        }
        return &triggersv1.InterceptorResponse{Continue: false}
    }

    logging.Infof("Incident %s is mapped to investigation '%s', returning InterceptorResponse `Continue: true`.", pdClient.GetIncidentID(), investigation.Name())
    return &triggersv1.InterceptorResponse{Continue: true}
}

func (pdi *interceptorHandler) routeByOrganization(ctx context.Context, pdClient *pagerduty.SdkClient) error {
    // Initialize OCM client
    ocmClientID := os.Getenv("CAD_OCM_CLIENT_ID")
    ocmClientSecret := os.Getenv("CAD_OCM_CLIENT_SECRET")
    ocmURL := os.Getenv("CAD_OCM_URL")
    
    ocmClient, err := ocm.New(ocmClientID, ocmClientSecret, ocmURL)
    if err != nil {
        return fmt.Errorf("failed to initialize OCM client: %w", err)
    }

    // Get cluster ID from alert
    clusterID, err := pdClient.RetrieveClusterID()
    if err != nil {
        return fmt.Errorf("failed to retrieve cluster ID: %w", err)
    }

    // Get cluster info to retrieve organization
    cluster, err := ocmClient.GetClusterInfo(clusterID)
    if err != nil {
        return fmt.Errorf("failed to get cluster info: %w", err)
    }

    // Get organization ID
    organization, ok := cluster.GetOrganization()
    if !ok {
        logging.Warn("No organization found for cluster, using default routing")
        return nil
    }
    
    orgID := organization.ID()
    logging.Infof("Cluster %s belongs to organization %s (%s)", clusterID, orgID, organization.Name())

    // Load routing configuration
    config, err := pdi.loadRoutingConfig()
    if err != nil {
        return fmt.Errorf("failed to load routing config: %w", err)
    }

    // Determine escalation policy
    policyID := pdi.getEscalationPolicyForOrg(orgID, config)
    
    if policyID == "" || policyID == config.DefaultPolicyID {
        logging.Infof("Organization %s uses default escalation policy", orgID)
        return nil
    }

    // Route to organization-specific escalation policy
    logging.Infof("Routing organization %s to escalation policy %s", orgID, policyID)
    err = pdClient.MoveToEscalationPolicy(policyID)
    if err != nil {
        return fmt.Errorf("failed to move to escalation policy %s: %w", policyID, err)
    }

    // Add note about routing
    note := fmt.Sprintf("🤖 Alert routed to organization-specific escalation policy (org: %s)", organization.Name())
    if err := pdClient.AddNote(note); err != nil {
        logging.Warnf("Failed to add routing note: %v", err)
    }

    return nil
}

func (pdi *interceptorHandler) loadRoutingConfig() (*routingConfig, error) {
    configYAML := os.Getenv("CAD_ORG_ROUTING_CONFIG")
    if configYAML == "" {
        return nil, fmt.Errorf("CAD_ORG_ROUTING_CONFIG not set")
    }

    config := &routingConfig{}
    err := yaml.Unmarshal([]byte(configYAML), config)
    if err != nil {
        return nil, fmt.Errorf("failed to parse routing config: %w", err)
    }

    return config, nil
}

func (pdi *interceptorHandler) getEscalationPolicyForOrg(orgID string, config *routingConfig) string {
    // Check exact match first
    if policyID, exists := config.Mappings[orgID]; exists {
        return policyID
    }

    // Check pattern matches
    for _, pattern := range config.Patterns {
        matched, err := regexp.MatchString(pattern.Regex, orgID)
        if err != nil {
            logging.Warnf("Invalid regex pattern %s: %v", pattern.Regex, err)
            continue
        }
        if matched {
            return pattern.PolicyID
        }
    }

    // Return default
    return config.DefaultPolicyID
}
```

**4. Update PagerDuty Client**

Make the `moveToEscalationPolicy` method public:

```go
// pkg/pagerduty/pagerduty.go

// MoveToEscalationPolicy moves the incident to a specified escalation policy (public wrapper)
func (c *SdkClient) MoveToEscalationPolicy(escalationPolicyID string) error {
    return c.moveToEscalationPolicy(escalationPolicyID)
}
```


## Alternatives Considered

### Alternative 1: Static Service-Based Routing

**Description:** Create separate PagerDuty services for each organization tier.

**Pros:**
- Simplest to configure
- Clear separation between tiers

**Cons:**
- Requires different integration keys per tier
- Must know organization at alert creation time
- Difficult to change organization tiers
- Scales poorly with many organizations

**Verdict:** ❌ Rejected due to poor scalability

### Alternative 2: Incident Webhook Post-Processing

**Description:** Use a separate webhook receiver to re-route incidents after creation.

**Pros:**
- No changes to alerting pipeline
- Can implement complex routing logic

**Cons:**
- Additional latency (incident created then moved)
- More complex architecture
- Potential for race conditions
- Extra webhook receiver to maintain

**Verdict:** ❌ Rejected due to unnecessary complexity

### Alternative 3: Organization-Aware Alert Manager

**Description:** Modify Alertmanager to route directly to org-specific PagerDuty services.

**Pros:**
- Routing happens early in pipeline
- No PagerDuty Event Orchestration required

**Cons:**
- Requires forking/patching Alertmanager
- Difficult to maintain custom Alertmanager build
- Tight coupling with alerting infrastructure

**Verdict:** ❌ Rejected due to maintenance burden


## References

- [PagerDuty Event Orchestration Documentation](https://support.pagerduty.com/docs/event-orchestration)
- [OCM API Documentation](https://api.openshift.com/)
- [CAD Architecture Overview](../README.md)
- [CAD Interceptor README](../interceptor/README.md)
- [Prometheus Alertmanager Configuration](https://prometheus.io/docs/alerting/latest/configuration/)

---

## Appendix

### Appendix A: PagerDuty API Endpoints

```
GET    /escalation_policies/{id}          - Get escalation policy details
PUT    /incidents/{id}                    - Update incident (including escalation policy)
POST   /incidents/{id}/notes              - Add note to incident
GET    /incidents/{id}/alerts             - Get alerts for incident
POST   /events/v2/enqueue                 - Send event to PagerDuty
```


### Appendix C: Example Alert Payload with org_id

```json
{
  "receiver": "pagerduty-cad",
  "status": "firing",
  "alerts": [
    {
      "status": "firing",
      "labels": {
        "alertname": "ClusterHealthCheckFailure",
        "severity": "critical",
        "cluster_id": "1a2b3c4d5e6f",
        "org_id": "premium-org-123"
      },
      "annotations": {
        "summary": "Cluster health check failed",
        "description": "Cluster 1a2b3c4d5e6f failed health check"
      }
    }
  ],
  "groupLabels": {
    "alertname": "ClusterHealthCheckFailure",
    "cluster_id": "1a2b3c4d5e6f",
    "org_id": "premium-org-123"
  },
  "commonAnnotations": {},
  "externalURL": "https://prometheus.example.com"
}
```

### Appendix D: Troubleshooting Guide

**Problem:** Alert not routed to expected escalation policy

**Debugging Steps:**
1. Check incident custom_details for org_id
   ```bash
   curl -H "Authorization: Token token=$PD_TOKEN" \
     https://api.pagerduty.com/incidents/{incident_id}/alerts
   ```

2. Verify org-escalation mapping
   ```bash
   kubectl get cm cad-org-escalation-mapping -n cad -o yaml
   ```

3. Check Event Orchestration logs in PagerDuty UI
   - Navigate to Automation → Event Orchestration
   - View execution logs for the incident

4. Verify escalation policy exists
   ```bash
   curl -H "Authorization: Token token=$PD_TOKEN" \
     https://api.pagerduty.com/escalation_policies/{policy_id}
   ```

**Problem:** org_id missing from alert payload

**Resolution:**
1. Check Prometheus recording rules are active
   ```bash
   kubectl exec -n monitoring prometheus-0 -- \
     promtool check rules /etc/prometheus/rules/*.yaml
   ```

2. Verify Alertmanager configuration
   ```bash
   kubectl get cm alertmanager-config -n monitoring -o yaml
   ```

3. Send test alert with org_id
   ```bash
   ./scripts/send-test-alert.sh --org-id premium-org-123
   ```

---
