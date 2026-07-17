package aiassisted

import (
	"fmt"
	"strings"
)

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
