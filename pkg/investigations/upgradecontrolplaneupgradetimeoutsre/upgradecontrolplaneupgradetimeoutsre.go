// Package upgradecontrolplaneupgradetimeoutsre contains the investigation for the
// UpgradeControlPlaneUpgradeTimeoutSRE alert.
//
// The alert is raised by the managed-upgrade-operator (MUO) when the control-plane
// portion of a Classic cluster upgrade exceeds its timeout. This investigation is
// read-only (informing stage): it inspects ClusterVersion, ClusterOperators and
// MachineConfigPools, names the most likely blocker in the PagerDuty note, and
// escalates. PDB-blocked drains are covered by chaining the pdbblockingnodedrain
// investigation after this one in the investigation config.
package upgradecontrolplaneupgradetimeoutsre

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	mcfgv1 "github.com/openshift/api/machineconfiguration/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	k8sclient "github.com/openshift/configuration-anomaly-detection/pkg/k8s"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	"github.com/openshift/configuration-anomaly-detection/pkg/types"
)

const (
	investigationName = "upgradecontrolplaneupgradetimeoutsre"
	masterPool        = "master"
	operatorOperand   = "operator"

	// checksTimeout bounds all cluster reads so a hung API call cannot block
	// the PD note and escalation.
	checksTimeout = 2 * time.Minute
)

// upgradeState is the read-only snapshot used to pick a verdict.
type upgradeState struct {
	DesiredVersion string
	Completed      bool   // history[0] is Completed for the desired version
	CVOFailing     string // ClusterVersion Failing=True message, if any
	CVOProgressing string // ClusterVersion Progressing message, if any

	// StaleStatus is set when ClusterVersion status has not yet observed the
	// latest spec (observedGeneration != generation), e.g. MUO has just set
	// desiredUpdate. Status-derived fields are then not trusted.
	StaleStatus bool
	Generation  int64
	ObservedGen int64

	DegradedOperators    []string // "name (reason)"
	UnavailableOperators []string // "name (reason)"
	LaggingOperators     []string // operators whose operand version != desired

	// MasterPool gates control-plane completion; other pools are reported in
	// the note but do not drive the verdict.
	MasterPool *poolState

	// ReadErrors names the resources that could not be read, so the verdict
	// is reported as inconclusive rather than "no blocker found".
	ReadErrors []string
}

// poolState summarises one MachineConfigPool's rollout.
type poolState struct {
	Name           string
	Machines       int32
	Updated        int32
	Degraded       int32
	IsUpdating     bool
	IsDegraded     bool
	NotUpdated     bool // Updated=False: the pool has not reached its target config
	IsPaused       bool // spec.paused: MCO will not roll out pending changes (a blocker only when NotUpdated)
	DegradedReason string
}

// stuck reports a pool that has not finished its rollout and is not progressing.
func (p poolState) stuck() bool {
	return p.NotUpdated && !p.IsUpdating
}

// Investigation implements the UpgradeControlPlaneUpgradeTimeoutSRE investigation.
type Investigation struct{}

// Run gates on cluster type, reads upgrade state and escalates with a verdict.
func (i *Investigation) Run(rb investigation.ResourceBuilder) (investigation.InvestigationResult, error) {
	result := investigation.InvestigationResult{}

	r, err := rb.WithCluster().WithK8sClient().WithNotes().Build()
	if err != nil {
		if msg, ok := investigation.ClusterAccessErrorMessage(err); ok {
			logging.Warnf("Cluster access error for %s: %v", i.Name(), err)
			result.Actions = []types.Action{
				executor.Note(msg),
				executor.Escalate(msg),
			}
			return result, nil
		}
		return result, investigation.WrapInfrastructure(err, "failed to build resources for "+i.Name())
	}

	// Management / service clusters: a stuck upgrade here is an incident with its own SOP.
	if r.IsInfrastructureCluster {
		r.Notes.AppendWarning("Cluster is a management/service cluster: treat as an incident and follow the infrastructure-cluster upgrade SOP. No further automated checks run.")
		result.Actions = append(
			executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), i.Name()),
			executor.Escalate("Control-plane upgrade timeout on an infrastructure cluster"),
		)
		result.StopInvestigations = errors.New("infrastructure cluster: manual incident handling")
		return result, nil
	}

	// The alert comes from MUO, which only manages Classic upgrades.
	if r.IsHCP {
		r.Notes.AppendWarning("Cluster is HCP: UpgradeControlPlaneUpgradeTimeoutSRE is a Classic (MUO) alert, manual review required.")
		result.Actions = append(
			executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), i.Name()),
			executor.Escalate("Unexpected HCP cluster for UpgradeControlPlaneUpgradeTimeoutSRE"),
		)
		return result, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), checksTimeout)
	defer cancel()
	state := upgradeState{}

	i.checkClusterVersion(ctx, r.K8sClient, &state, r.Notes)
	desiredVersion := state.DesiredVersion
	if state.StaleStatus {
		desiredVersion = "" // do not measure operator lag against a stale target
	}
	i.checkClusterOperators(ctx, r.K8sClient, desiredVersion, &state, r.Notes)
	i.checkMachineConfigPools(ctx, r.K8sClient, &state, r.Notes)

	verdict := classify(state)
	r.Notes.AppendWarning("Likely blocker: %s", verdict)

	result.Actions = append(
		executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), i.Name()),
		executor.Escalate("UpgradeControlPlaneUpgradeTimeoutSRE investigation complete: manual review required"),
	)
	return result, nil
}

// checkClusterVersion records the desired version, whether it completed, and the
// CVO Failing / Progressing messages.
func (i *Investigation) checkClusterVersion(ctx context.Context, k8sClient k8sclient.Client, state *upgradeState, notes *notewriter.NoteWriter) {
	cv := &configv1.ClusterVersion{}
	if err := k8sClient.Get(ctx, client.ObjectKey{Name: "version"}, cv); err != nil {
		notes.AppendWarning("ClusterVersion: failed to get: %v", err)
		state.ReadErrors = append(state.ReadErrors, "ClusterVersion")
		return
	}

	state.DesiredVersion = cv.Status.Desired.Version
	if cv.Status.ObservedGeneration != cv.Generation {
		state.StaleStatus = true
		state.Generation = cv.Generation
		state.ObservedGen = cv.Status.ObservedGeneration
		notes.AppendWarning("ClusterVersion: status not yet updated for the latest spec (observedGeneration %d, generation %d); completion is not evaluated",
			cv.Status.ObservedGeneration, cv.Generation)
		return
	}
	if len(cv.Status.History) > 0 {
		latest := cv.Status.History[0]
		state.Completed = latest.State == configv1.CompletedUpdate && latest.Version == state.DesiredVersion
	}

	for _, cond := range cv.Status.Conditions {
		switch {
		case cond.Type == "Failing" && cond.Status == configv1.ConditionTrue:
			state.CVOFailing = oneLine(cond.Message)
		case cond.Type == configv1.OperatorProgressing && cond.Status == configv1.ConditionTrue:
			state.CVOProgressing = oneLine(cond.Message)
		}
	}

	switch {
	case state.CVOFailing != "":
		notes.AppendWarning("ClusterVersion: upgrade to %s is Failing: %s", state.DesiredVersion, state.CVOFailing)
	case state.Completed:
		notes.AppendSuccess("ClusterVersion: upgrade to %s is Completed", state.DesiredVersion)
	case state.CVOProgressing != "":
		notes.AppendWarning("ClusterVersion: upgrade to %s in progress: %s", state.DesiredVersion, state.CVOProgressing)
	default:
		notes.AppendWarning("ClusterVersion: upgrade to %s not completed and CVO is not reporting Progressing", state.DesiredVersion)
	}
}

// checkClusterOperators reports degraded, unavailable and not-yet-upgraded operators.
// desiredVersion is passed explicitly so the check does not depend on call order;
// when it is empty, version lag is not evaluated.
func (i *Investigation) checkClusterOperators(ctx context.Context, k8sClient k8sclient.Client, desiredVersion string, state *upgradeState, notes *notewriter.NoteWriter) {
	coList := &configv1.ClusterOperatorList{}
	if err := k8sClient.List(ctx, coList); err != nil {
		notes.AppendWarning("ClusterOperators: failed to list: %v", err)
		state.ReadErrors = append(state.ReadErrors, "ClusterOperators")
		return
	}

	for _, co := range coList.Items {
		for _, cond := range co.Status.Conditions {
			// Reason only: condition messages can carry hostnames and endpoints.
			detail := fmt.Sprintf("%s (%s)", co.Name, cond.Reason)
			switch {
			case cond.Type == configv1.OperatorDegraded && cond.Status == configv1.ConditionTrue:
				state.DegradedOperators = append(state.DegradedOperators, detail)
			case cond.Type == configv1.OperatorAvailable && cond.Status == configv1.ConditionFalse:
				state.UnavailableOperators = append(state.UnavailableOperators, detail)
			}
		}

		if desiredVersion != "" {
			if v := operandVersion(co); v != desiredVersion {
				if v == "" {
					v = "unknown"
				}
				state.LaggingOperators = append(state.LaggingOperators, fmt.Sprintf("%s (at %s)", co.Name, v))
			}
		}
	}

	if len(state.UnavailableOperators) > 0 {
		notes.AppendWarning("ClusterOperators: %d unavailable:\n  %s", len(state.UnavailableOperators), strings.Join(state.UnavailableOperators, "\n  "))
	}
	if len(state.DegradedOperators) > 0 {
		notes.AppendWarning("ClusterOperators: %d degraded:\n  %s", len(state.DegradedOperators), strings.Join(state.DegradedOperators, "\n  "))
	}
	if len(state.LaggingOperators) > 0 {
		notes.AppendWarning("ClusterOperators: %d/%d not yet at %s:\n  %s", len(state.LaggingOperators), len(coList.Items), desiredVersion, strings.Join(state.LaggingOperators, "\n  "))
	}
	if len(state.UnavailableOperators) == 0 && len(state.DegradedOperators) == 0 && len(state.LaggingOperators) == 0 {
		notes.AppendSuccess("ClusterOperators: all %d available, not degraded, and at the desired version", len(coList.Items))
	}
}

// checkMachineConfigPools reports rollout progress, highlighting the master pool,
// which must finish before the control-plane upgrade completes.
func (i *Investigation) checkMachineConfigPools(ctx context.Context, k8sClient k8sclient.Client, state *upgradeState, notes *notewriter.NoteWriter) {
	mcpList := &mcfgv1.MachineConfigPoolList{}
	if err := k8sClient.List(ctx, mcpList); err != nil {
		notes.AppendWarning("MachineConfigPools: failed to list: %v", err)
		state.ReadErrors = append(state.ReadErrors, "MachineConfigPools")
		return
	}

	var lines []string
	healthy := true
	for _, mcp := range mcpList.Items {
		ps := poolState{
			Name:     mcp.Name,
			Machines: mcp.Status.MachineCount,
			Updated:  mcp.Status.UpdatedMachineCount,
			Degraded: mcp.Status.DegradedMachineCount,
			IsPaused: mcp.Spec.Paused,
		}
		for _, cond := range mcp.Status.Conditions {
			switch {
			case cond.Type == mcfgv1.MachineConfigPoolUpdating && cond.Status == corev1.ConditionTrue:
				ps.IsUpdating = true
			case cond.Type == mcfgv1.MachineConfigPoolDegraded && cond.Status == corev1.ConditionTrue:
				ps.IsDegraded = true
				ps.DegradedReason = oneLine(cond.Message)
			case cond.Type == mcfgv1.MachineConfigPoolUpdated && cond.Status == corev1.ConditionFalse:
				ps.NotUpdated = true
			}
		}

		if mcp.Name == masterPool {
			state.MasterPool = &ps
		}

		if ps.IsUpdating || ps.IsDegraded || ps.NotUpdated {
			healthy = false
			line := fmt.Sprintf("%s: %d/%d updated", ps.Name, ps.Updated, ps.Machines)
			if ps.IsPaused {
				line += ", PAUSED"
			}
			if ps.stuck() && !ps.IsDegraded {
				line += ", not progressing"
			}
			if ps.IsDegraded {
				line += fmt.Sprintf(", DEGRADED (%d machine(s)): %s", ps.Degraded, ps.DegradedReason)
			}
			lines = append(lines, line)
		}
	}

	if healthy {
		notes.AppendSuccess("MachineConfigPools: all %d pools updated and not degraded", len(mcpList.Items))
		return
	}
	notes.AppendWarning("MachineConfigPools: rollout not finished:\n  %s", strings.Join(lines, "\n  "))
}

// classify picks the single most likely blocker, most specific signal first.
func classify(s upgradeState) string {
	switch {
	case s.DesiredVersion == "":
		return "could not read ClusterVersion; investigate manually"
	case s.StaleStatus:
		return fmt.Sprintf("inconclusive: ClusterVersion status is stale (observedGeneration %d, generation %d); CVO has not yet picked up the requested update, recheck shortly",
			s.ObservedGen, s.Generation)
	case s.Completed:
		return fmt.Sprintf("none: upgrade to %s has completed, MUO should resolve the alert on its next reconcile", s.DesiredVersion)
	case s.CVOFailing != "":
		return "CVO reports Failing: " + s.CVOFailing
	case len(s.UnavailableOperators) > 0:
		return "unavailable operator(s): " + strings.Join(s.UnavailableOperators, "; ")
	case len(s.DegradedOperators) > 0:
		return "degraded operator(s): " + strings.Join(s.DegradedOperators, "; ")
	case s.MasterPool != nil && s.MasterPool.IsDegraded:
		return "master MachineConfigPool degraded: " + s.MasterPool.DegradedReason
	case s.MasterPool != nil && s.MasterPool.IsPaused && s.MasterPool.NotUpdated:
		return fmt.Sprintf("master MachineConfigPool is paused at %d/%d nodes; pending changes will not roll out until it is unpaused",
			s.MasterPool.Updated, s.MasterPool.Machines)
	case s.MasterPool != nil && s.MasterPool.stuck():
		return fmt.Sprintf("master MachineConfigPool not updated (Updated=False) and not progressing at %d/%d nodes; check machine-config-controller logs",
			s.MasterPool.Updated, s.MasterPool.Machines)
	case s.MasterPool != nil && s.MasterPool.IsUpdating:
		return fmt.Sprintf("master MachineConfigPool rollout stalled at %d/%d nodes; check for drain blockers (see pdbblockingnodedrain note)",
			s.MasterPool.Updated, s.MasterPool.Machines)
	case len(s.ReadErrors) > 0:
		return "inconclusive: could not read " + strings.Join(s.ReadErrors, ", ") + "; investigate manually"
	case len(s.LaggingOperators) > 0:
		return fmt.Sprintf("%d operator(s) not yet at %s and none degraded: upgrade may be slow rather than stuck", len(s.LaggingOperators), s.DesiredVersion)
	default:
		return "no blocker found in ClusterVersion, ClusterOperators or MachineConfigPools; check MUO logs and the UpgradeConfig"
	}
}

// operandVersion returns the ClusterOperator's "operator" operand version.
func operandVersion(co configv1.ClusterOperator) string {
	for _, v := range co.Status.Versions {
		if v.Name == operatorOperand {
			return v.Version
		}
	}
	return ""
}

// oneLine collapses whitespace and truncates s for a single-line PD note.
func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	const maxLen = 300
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

// Name returns the investigation name, which must match the package directory.
func (i *Investigation) Name() string {
	return investigationName
}

// AlertTitle returns the PagerDuty alert title this investigation handles.
func (i *Investigation) AlertTitle() string {
	return "UpgradeControlPlaneUpgradeTimeoutSRE"
}

// Description returns a one-line summary of the investigation.
func (i *Investigation) Description() string {
	return "Triages a stalled Classic control-plane upgrade from ClusterVersion, ClusterOperators and MachineConfigPools"
}

// IsExperimental reports whether the investigation is gated behind CAD_EXPERIMENTAL_ENABLED.
func (i *Investigation) IsExperimental() bool {
	return false
}
