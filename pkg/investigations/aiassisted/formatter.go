package aiassisted

import (
	"encoding/json"
	"fmt"
	"strings"
)

func extractJSON(response string) (string, error) {
	jsonEnd := strings.LastIndex(response, "}")
	if jsonEnd == -1 {
		return "", fmt.Errorf("no JSON found in response")
	}

	searchFrom := 0
	for {
		jsonStart := strings.Index(response[searchFrom:], "{")
		if jsonStart == -1 {
			break
		}
		jsonStart += searchFrom
		candidate := response[jsonStart : jsonEnd+1]
		if json.Unmarshal([]byte(candidate), &json.RawMessage{}) == nil {
			return candidate, nil
		}
		searchFrom = jsonStart + 1
	}

	return "", fmt.Errorf("no valid JSON found in response")
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
				fmt.Fprintf(&sb, "   ````bash\n   %s\n   ````\n", *step.Command)
			}
		}
		sb.WriteString("\n")
	}

	// Escalation Decision
	sb.WriteString("## Escalation Decision\n\n")
	if result.NeedsEscalation {
		sb.WriteString("⚠️ ESCALATE\n")
	} else {
		sb.WriteString("✅ No escalation needed\n")
	}

	return sb.String()
}
