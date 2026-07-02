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

	// Root Cause Summary
	sb.WriteString("## Root Cause Summary\n\n")
	fmt.Fprintf(&sb, "%s\n\n", result.RootCause.Summary)

	// Root Cause Confidence
	fmt.Fprintf(&sb, "**Confidence**: %s (%.0f%%)\n\n",
		strings.ToUpper(result.RootCause.Confidence),
		result.RootCause.ConfidenceScore*100)

	// Action Steps
	sb.WriteString("## Action Steps\n\n")
	if len(result.Remediation.Steps) == 0 {
		sb.WriteString("No action steps available.\n\n")
	} else {
		for i, step := range result.Remediation.Steps {
			fmt.Fprintf(&sb, "%d. %s\n", i+1, step.Action)
			if step.Command != nil && *step.Command != "" {
				fmt.Fprintf(&sb, "   ```bash\n   %s\n   ```\n", *step.Command)
			}
		}
		sb.WriteString("\n")
	}

	// Escalation Decision
	sb.WriteString("## Escalation Decision\n\n")
	if result.Escalation.Recommended {
		sb.WriteString("⚠️ ESCALATE\n")
	} else {
		sb.WriteString("✅ No escalation needed\n")
	}

	return sb.String()
}
