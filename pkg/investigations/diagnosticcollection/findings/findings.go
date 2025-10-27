package findings

import (
	"fmt"
	"strings"
)

// Severity indicates how critical a finding is
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// Finding represents a single diagnostic finding
type Finding struct {
	// Severity of the finding
	Severity Severity
	// Title is a short summary of the finding
	Title string
	// Message is the detailed description
	Message string
	// Recommendation suggests what action to take
	Recommendation string
}

// Findings is a collection of diagnostic findings
type Findings struct {
	items []Finding
}

// New creates a new Findings collection
func New() *Findings {
	return &Findings{
		items: make([]Finding, 0),
	}
}

// Add adds a finding to the collection
func (f *Findings) Add(finding Finding) {
	f.items = append(f.items, finding)
}

// AddInfo adds an informational finding
func (f *Findings) AddInfo(title, message string) {
	f.Add(Finding{
		Severity: SeverityInfo,
		Title:    title,
		Message:  message,
	})
}

// AddWarning adds a warning finding
func (f *Findings) AddWarning(title, message, recommendation string) {
	f.Add(Finding{
		Severity:       SeverityWarning,
		Title:          title,
		Message:        message,
		Recommendation: recommendation,
	})
}

// AddCritical adds a critical finding
func (f *Findings) AddCritical(title, message, recommendation string) {
	f.Add(Finding{
		Severity:       SeverityCritical,
		Title:          title,
		Message:        message,
		Recommendation: recommendation,
	})
}

// IsEmpty returns true if there are no findings
func (f *Findings) IsEmpty() bool {
	return len(f.items) == 0
}

// Count returns the number of findings
func (f *Findings) Count() int {
	return len(f.items)
}

// GetAll returns all findings
func (f *Findings) GetAll() []Finding {
	return f.items
}

// HasCritical returns true if any findings are critical
func (f *Findings) HasCritical() bool {
	for _, finding := range f.items {
		if finding.Severity == SeverityCritical {
			return true
		}
	}
	return false
}

// HasWarnings returns true if any findings are warnings
func (f *Findings) HasWarnings() bool {
	for _, finding := range f.items {
		if finding.Severity == SeverityWarning {
			return true
		}
	}
	return false
}

// FormatForPagerDuty formats all findings as a PagerDuty note
func (f *Findings) FormatForPagerDuty() string {
	if f.IsEmpty() {
		return "✅ No issues detected during diagnostic collection.\n"
	}

	var sb strings.Builder

	// Group by severity
	critical := f.getBySeverity(SeverityCritical)
	warnings := f.getBySeverity(SeverityWarning)
	info := f.getBySeverity(SeverityInfo)

	if len(critical) > 0 {
		sb.WriteString(fmt.Sprintf("🔴 Critical Issues (%d)\n", len(critical)))
		sb.WriteString("==================\n")
		for i, finding := range critical {
			sb.WriteString(f.formatFinding(i+1, finding))
		}
		sb.WriteString("\n")
	}

	if len(warnings) > 0 {
		sb.WriteString(fmt.Sprintf("⚠️ Warnings (%d)\n", len(warnings)))
		sb.WriteString("============\n")
		for i, finding := range warnings {
			sb.WriteString(f.formatFinding(i+1, finding))
		}
		sb.WriteString("\n")
	}

	if len(info) > 0 {
		sb.WriteString(fmt.Sprintf("ℹ️ Information (%d)\n", len(info)))
		sb.WriteString("===============\n")
		for i, finding := range info {
			sb.WriteString(f.formatFinding(i+1, finding))
		}
	}

	return sb.String()
}

func (f *Findings) getBySeverity(severity Severity) []Finding {
	var result []Finding
	for _, finding := range f.items {
		if finding.Severity == severity {
			result = append(result, finding)
		}
	}
	return result
}

func (f *Findings) formatFinding(index int, finding Finding) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("%d. %s\n", index, finding.Title))

	if finding.Message != "" {
		// Indent message lines
		lines := strings.Split(finding.Message, "\n")
		for _, line := range lines {
			if line != "" {
				sb.WriteString(fmt.Sprintf("   %s\n", line))
			}
		}
	}

	if finding.Recommendation != "" {
		sb.WriteString(fmt.Sprintf("   💡 %s\n", finding.Recommendation))
	}

	sb.WriteString("\n")
	return sb.String()
}
