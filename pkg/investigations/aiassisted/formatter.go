package aiassisted

import (
	"fmt"
	"strings"
)

// FormatPagerDutyNote converts CoraInvestigationResult into a well-formatted
// PagerDuty note. PD notes are plain text (no markdown rendering), so this
// uses emoji, caps, and indentation for structure instead of markdown syntax.
// reportClusterID is the authoritative cluster external ID used in the osdctl
// footer command — it must match the ID used for the backplane report.
func FormatPagerDutyNote(result *CoraInvestigationResult, reportClusterID string) string {
	var sb strings.Builder

	// Header
	sb.WriteString("🤖 AI-Assisted Investigation\n")
	sb.WriteString("════════════════════════════════\n\n")

	// Alert & Confidence
	fmt.Fprintf(&sb, "Alert: %s\n", result.AlertName)
	fmt.Fprintf(&sb, "Confidence: %s\n\n", strings.ToUpper(result.Confidence))

	// Summary — the key triage info
	fmt.Fprintf(&sb, "%s\n\n", result.Summary)

	// Escalation recommendation from Cora (the PD incident is always escalated
	// before the AI investigation runs, so this reflects Cora's assessment, not
	// the current incident state)
	if result.NeedsEscalation {
		sb.WriteString("⚠️ Cora recommends escalation\n")
	} else {
		sb.WriteString("✅ Cora: no further escalation needed\n")
	}

	// Footer with cluster report access
	sb.WriteString("\n────────────────────────────────\n")
	fmt.Fprintf(&sb, "Full details: osdctl cluster reports list --cluster-id %s\n", reportClusterID)

	return sb.String()
}

// FormatInvestigationReport converts CoraInvestigationResult into human-readable markdown
func FormatInvestigationReport(result *CoraInvestigationResult) string {
	var sb strings.Builder

	// Cluster ID
	fmt.Fprintf(&sb, "**Cluster ID**: %s\n", result.ClusterID)

	// Alert Name
	fmt.Fprintf(&sb, "**Alert Name**: %s\n\n", result.AlertName)

	// Summary
	sb.WriteString("## Summary\n\n")
	fmt.Fprintf(&sb, "%s\n\n", result.Summary)

	// Confidence
	fmt.Fprintf(&sb, "**Confidence**: %s\n\n",
		strings.ToUpper(result.Confidence))

	// Reasoning
	sb.WriteString("**Reasoning**: ")
	fmt.Fprintf(&sb, "%s\n\n", result.Reasoning)

	// Evidence
	sb.WriteString("## Evidence\n\n")
	fmt.Fprintf(&sb, "%s\n\n", result.Evidence)

	// Action Steps
	sb.WriteString("## Action Steps\n\n")
	if len(result.RemediationSteps) == 0 {
		sb.WriteString("No action steps available.\n\n")
	} else {
		for i, step := range result.RemediationSteps {
			fmt.Fprintf(&sb, "%d. %s\n", i+1, step.Action)
			if step.Command != nil && *step.Command != "" {
				fmt.Fprintf(&sb, "   ```bash\n   %s\n   ```\n", *step.Command)
			}
		}
		sb.WriteString("\n")
	}

	// Escalation Decision
	sb.WriteString("## Escalation Decision\n\n")
	if result.NeedsEscalation {
		sb.WriteString("⚠️ ESCALATE\n")
		if result.EscalationReason != nil && *result.EscalationReason != "" {
			fmt.Fprintf(&sb, "**Reason**: %s\n", *result.EscalationReason)
		}
	} else {
		sb.WriteString("✅ No escalation needed\n")
	}

	return sb.String()
}
