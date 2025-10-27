package analyzers

import (
	"fmt"
	"strings"

	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/diagnosticcollection/findings"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/diagnosticcollection/parsers"
)

// ClusterOperatorAnalyzer analyzes ClusterOperator resources for health issues
type ClusterOperatorAnalyzer struct{}

// NewClusterOperatorAnalyzer creates a new ClusterOperator analyzer
func NewClusterOperatorAnalyzer() *ClusterOperatorAnalyzer {
	return &ClusterOperatorAnalyzer{}
}

// Name returns the analyzer name
func (a *ClusterOperatorAnalyzer) Name() string {
	return "ClusterOperator"
}

// Analyze examines ClusterOperator data and returns findings
func (a *ClusterOperatorAnalyzer) Analyze(inspectDir string) (*findings.Findings, error) {
	f := findings.New()

	// Parse ClusterOperators
	operators, err := parsers.ParseClusterOperators(inspectDir)
	if err != nil {
		return nil, fmt.Errorf("failed to parse clusteroperators: %w", err)
	}

	// Get degraded and unavailable operators
	degradedOps := parsers.GetDegradedOperators(operators)
	unavailableOps := parsers.GetUnavailableOperators(operators)

	// Report summary
	totalOps := len(operators)
	healthyOps := totalOps - len(degradedOps) - len(unavailableOps)
	f.AddInfo(
		"Cluster Operators Summary",
		fmt.Sprintf("Total: %d | Healthy: %d | Degraded: %d | Unavailable: %d",
			totalOps, healthyOps, len(degradedOps), len(unavailableOps)),
	)

	// Report degraded operators
	if len(degradedOps) > 0 {
		for _, op := range degradedOps {
			f.AddCritical(
				fmt.Sprintf("Operator Degraded: %s", op.Name),
				fmt.Sprintf("Reason: %s\nMessage: %s", op.DegradedReason, op.DegradedMessage),
				a.getRecommendation(op.Name, op.DegradedReason),
			)
		}
	}

	// Report unavailable operators (that aren't already degraded)
	for _, op := range unavailableOps {
		// Skip if already reported as degraded
		if op.IsDegraded {
			continue
		}

		availCond := op.GetCondition("Available")
		message := ""
		reason := ""
		if availCond != nil {
			message = availCond.Message
			reason = availCond.Reason
		}

		f.AddWarning(
			fmt.Sprintf("Operator Unavailable: %s", op.Name),
			fmt.Sprintf("Reason: %s\nMessage: %s", reason, message),
			fmt.Sprintf("Check operator pods: oc -n openshift-%s get pods", op.Name),
		)
	}

	return f, nil
}

// getRecommendation provides operator-specific recommendations based on name and reason
func (a *ClusterOperatorAnalyzer) getRecommendation(operatorName, reason string) string {
	// Common namespace for operators
	namespace := fmt.Sprintf("openshift-%s", operatorName)

	// Operator-specific recommendations
	switch operatorName {
	case "authentication":
		return fmt.Sprintf("Check authentication operator: oc -n %s get pods\nCheck OAuth resources: oc get oauth cluster -o yaml", namespace)
	case "ingress":
		return fmt.Sprintf("Check ingress operator: oc -n openshift-ingress-operator get pods\nCheck routers: oc -n openshift-ingress get pods")
	case "kube-apiserver", "openshift-apiserver":
		return fmt.Sprintf("Check API server pods: oc -n %s get pods\nCheck API server logs for errors", namespace)
	case "machine-config":
		if strings.Contains(strings.ToLower(reason), "pool") {
			return "Check machine config pools: oc get mcp\nCheck nodes: oc get nodes"
		}
		return fmt.Sprintf("Check machine config operator: oc -n %s get pods", namespace)
	case "monitoring":
		return "Check monitoring stack: oc -n openshift-monitoring get pods\nCheck prometheus: oc -n openshift-monitoring get prometheus"
	case "etcd":
		return "Check etcd pods: oc -n openshift-etcd get pods\nCheck etcd health: oc -n openshift-etcd exec -it <etcd-pod> -- etcdctl endpoint health"
	default:
		return fmt.Sprintf("Check operator pods: oc -n %s get pods\nReview operator logs for details", namespace)
	}
}
