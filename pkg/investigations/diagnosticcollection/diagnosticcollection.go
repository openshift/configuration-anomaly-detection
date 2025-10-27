// Package diagnosticcollection provides generic diagnostic collection using oc adm inspect
// for various alert types. It uses a mapping system to determine which resources to collect
// based on the alert type, then analyzes the collected data and posts findings to PagerDuty.
package diagnosticcollection

import (
	"fmt"
	"strings"

	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/diagnosticcollection/analyzers"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/diagnosticcollection/findings"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/diagnosticcollection/inspect"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
)

type Investigation struct{}

func (c *Investigation) Run(rb investigation.ResourceBuilder) (investigation.InvestigationResult, error) {
	result := investigation.InvestigationResult{}

	// Build resources with K8s client (needed for oc commands)
	r, err := rb.WithK8sClient().Build()
	if err != nil {
		return result, fmt.Errorf("failed to build resources: %w", err)
	}

	// Initialize PagerDuty note writer
	notes := notewriter.New(r.Name, logging.RawLogger)
	defer func() { r.Notes = notes }()

	// Get the alert name from the investigation name
	// In a real scenario, this would come from the PagerDuty webhook payload
	// For now, we'll use a default or extract from context
	alertName := "UpgradeConfigSyncFailureOver4HrSRE" // TODO: Get from payload

	// Find mapping for this alert
	mapping := GetMappingForAlert(alertName)
	if mapping == nil {
		notes.AppendWarning("No diagnostic mapping found for alert: %s", alertName)
		return result, r.PdClient.EscalateIncidentWithNote(notes.String())
	}

	logging.Infof("Using mapping: %s - %s", mapping.AlertPattern, mapping.Description)
	notes.AppendAutomation("Collecting diagnostics: %s", mapping.Description)

	// Create inspect executor
	executor := inspect.New(r.K8sClient)
	defer func() {
		// Cleanup will be called even if we return early
	}()

	// Run oc adm inspect
	inspectDir, err := executor.Execute(mapping.Resources)
	if err != nil {
		notes.AppendWarning("Failed to collect diagnostics: %v", err)
		logging.Errorf("oc adm inspect failed: %v", err)
		return result, r.PdClient.EscalateIncidentWithNote(notes.String())
	}
	defer executor.Cleanup(inspectDir)

	notes.AppendSuccess("Diagnostic data collected successfully")
	logging.Infof("Diagnostics collected in: %s", inspectDir)

	// Run analyzers
	allFindings := findings.New()

	// Determine which analyzers to run based on collected resources
	analyzerList := c.getAnalyzersForResources(mapping.Resources)

	for _, analyzer := range analyzerList {
		logging.Infof("Running analyzer: %s", analyzer.Name())

		analyzerFindings, err := analyzer.Analyze(inspectDir)
		if err != nil {
			logging.Warnf("Analyzer %s failed: %v", analyzer.Name(), err)
			notes.AppendWarning("Analysis failed for %s: %v", analyzer.Name(), err)
			continue
		}

		// Merge findings
		for _, finding := range analyzerFindings.GetAll() {
			allFindings.Add(finding)
		}
	}

	// Format findings for PagerDuty
	if !allFindings.IsEmpty() {
		notes.AppendAutomation("Diagnostic Analysis Results (%d findings)", allFindings.Count())
		findingsText := allFindings.FormatForPagerDuty()
		// Append the formatted findings directly to notes
		notes.AppendAutomation("%s", findingsText)
	} else {
		notes.AppendSuccess("No issues found during diagnostic analysis")
	}

	// Escalate to SRE with all findings
	return result, r.PdClient.EscalateIncidentWithNote(notes.String())
}

// getAnalyzersForResources returns the appropriate analyzers based on resources being inspected
func (c *Investigation) getAnalyzersForResources(resources []string) []analyzers.ResourceAnalyzer {
	var analyzerList []analyzers.ResourceAnalyzer

	for _, resource := range resources {
		resourceLower := strings.ToLower(resource)

		if strings.Contains(resourceLower, "clusterversion") {
			analyzerList = append(analyzerList, analyzers.NewClusterVersionAnalyzer())
		}

		if strings.Contains(resourceLower, "clusteroperator") {
			analyzerList = append(analyzerList, analyzers.NewClusterOperatorAnalyzer())
		}

		// Easy to add more analyzers for other resource types here
	}

	return analyzerList
}

func (c *Investigation) Name() string {
	return "diagnosticcollection"
}

func (c *Investigation) Description() string {
	return "Generic diagnostic collection using oc adm inspect for various alerts"
}

func (c *Investigation) ShouldInvestigateAlert(alert string) bool {
	// Check if there's a mapping for this alert
	mapping := GetMappingForAlert(alert)
	return mapping != nil
}

func (c *Investigation) IsExperimental() bool {
	// TODO: Update to false when graduating to production.
	return true
}

