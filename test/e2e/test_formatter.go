package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/aiassisted"
)

func main() {
	jsonInput := `{
		"investigation_id": "Q1RNC3P1LLTK2V",
		"cluster_id": "2r68ajgq9vtsej9shsd9pvdcpjdr9rt1",
		"alert_name": "FallbackTestAlert",
		"timestamp": "2026-06-26T20:18:40.228368Z",
		"duration_seconds": 103.949270809,
		"status": "completed",
		"root_cause": {
			"summary": "FallbackTestAlert is not a production monitoring alert. This appears to be a synthetic or test alert used for testing the AI agent investigation workflow. The cluster (eth-cora-test, ID: 2r68ajgq9vtsej9shsd9pvdcpjdr9rt1) is in a healthy 'ready' state running OpenShift 4.20.25 with no observable issues. No alert definition exists in the standard PrometheusRule configurations, SREP alert skills library, or monitoring namespaces. The alert name suggests it's a fallback test case rather than an actual cluster problem.",
			"category": "other",
			"confidence": "high",
			"confidence_score": 0.95,
			"reasoning": "High confidence assessment based on multiple lines of evidence: (1) Alert name 'FallbackTestAlert' follows test naming conventions, (2) No alert definition found in PrometheusRule resources, monitoring configmaps, or SREP alert skills (searched 16 production alert skills), (3) Cluster status is 'ready' with no provision errors, (4) OSD metrics exporter running normally, (5) Empty investigation payload suggests automated test invocation. The 0.95 confidence reflects certainty this is a test alert, with minimal uncertainty about the test's specific purpose."
		},
		"remediation": {
			"steps": [
				{
					"action": "Verify this is a test alert invocation by checking the source system that triggered this investigation (likely an automated test suite or CI/CD pipeline)",
					"command": null,
					"risk_level": "low",
					"requires_elevation": false
				},
				{
					"action": "If this alert is appearing in production monitoring systems, remove or disable it as it does not correspond to any real cluster condition",
					"command": null,
					"risk_level": "low",
					"requires_elevation": false
				},
				{
					"action": "No cluster remediation required - cluster is healthy and no actual issues detected",
					"command": null,
					"risk_level": "low",
					"requires_elevation": false
				}
			],
			"requires_elevation": false,
			"estimated_impact": "no_downtime",
			"automation_ready": true
		},
		"evidence": [],
		"escalation": {
			"recommended": false,
			"reason": "none",
			"urgency": "none",
			"target_team": null
		}
	}`

	var result aiassisted.CoraInvestigationResult
	if err := json.Unmarshal([]byte(jsonInput), &result); err != nil {
		fmt.Printf("Error parsing JSON: %v\n", err)
		os.Exit(1)
	}

	markdown := aiassisted.FormatInvestigationReport(&result)

	homeDir, _ := os.UserHomeDir()
	outputPath := homeDir + "/Desktop/cora_output.md"
	if err := os.WriteFile(outputPath, []byte(markdown), 0644); err != nil {
		fmt.Printf("Error writing file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Markdown saved to: %s\n", outputPath)
	fmt.Println(markdown)
}
