package utils

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/api/compute/v1"
)

const firewallRulePrefix = "cad-e2e-deny-egress"

// ComputeAPI interface to make testing easier
type ComputeAPI interface {
	InsertFirewallRule(ctx context.Context, project string, rule *compute.Firewall) (*compute.Operation, error)
	DeleteFirewallRule(ctx context.Context, project, name string) (*compute.Operation, error)
	WaitForGlobalOp(ctx context.Context, project, operationName string) (*compute.Operation, error)
}

// GCPClientWrapper wraps the GCP Compute API client to implement our ComputeAPI interface
type GCPClientWrapper struct {
	Client          *compute.FirewallsService
	GlobalOpsClient *compute.GlobalOperationsService
}

// InsertFirewallRule implements ComputeAPI
func (w *GCPClientWrapper) InsertFirewallRule(ctx context.Context, project string, rule *compute.Firewall) (*compute.Operation, error) {
	return w.Client.Insert(project, rule).Context(ctx).Do()
}

// DeleteFirewallRule implements ComputeAPI
func (w *GCPClientWrapper) DeleteFirewallRule(ctx context.Context, project, name string) (*compute.Operation, error) {
	return w.Client.Delete(project, name).Context(ctx).Do()
}

// WaitForGlobalOp implements ComputeAPI
func (w *GCPClientWrapper) WaitForGlobalOp(ctx context.Context, project, operationName string) (*compute.Operation, error) {
	return w.GlobalOpsClient.Wait(project, operationName).Context(ctx).Do()
}

// NewGCPClientWrapper creates a new GCPClientWrapper that implements ComputeAPI
func NewGCPClientWrapper(service *compute.Service) *GCPClientWrapper {
	return &GCPClientWrapper{
		Client:          service.Firewalls,
		GlobalOpsClient: service.GlobalOperations,
	}
}

func waitForOp(ctx context.Context, client ComputeAPI, project string, op *compute.Operation) error {
	for op.Status != "DONE" {
		next, err := client.WaitForGlobalOp(ctx, project, op.Name)
		if err != nil {
			return fmt.Errorf("waiting for operation %q: %w", op.Name, err)
		}
		op = next
	}
	if op.Error != nil {
		msgs := make([]string, len(op.Error.Errors))
		for i, e := range op.Error.Errors {
			msgs[i] = fmt.Sprintf("%s: %s", e.Code, e.Message)
		}
		return fmt.Errorf("operation %q failed: %s", op.Name, strings.Join(msgs, "; "))
	}
	return nil
}

// BlockEgressGCP creates high-priority deny-all egress firewall rules (IPv4 and IPv6) on the
// specified VPC network. Returns the firewall rule names for use with RestoreEgressGCP.
func BlockEgressGCP(ctx context.Context, client ComputeAPI, project, network string) ([]string, error) {
	var suffix [4]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return nil, fmt.Errorf("generating random suffix: %w", err)
	}
	base := fmt.Sprintf("%s-%x", firewallRulePrefix, suffix)

	rules := []struct {
		name   string
		destIP string
	}{
		{base, "0.0.0.0/0"},
		{base + "-v6", "::/0"},
	}

	names := make([]string, 0, len(rules))
	for _, r := range rules {
		rule := &compute.Firewall{
			Name:      r.name,
			Network:   network,
			Direction: "EGRESS",
			Priority:  0,
			Denied: []*compute.FirewallDenied{
				{IPProtocol: "all"},
			},
			DestinationRanges: []string{r.destIP},
			// Priority 0 is the int64 zero value, which omitempty would drop.
			// ForceSendFields ensures it is serialized so GCP uses priority 0 (highest) instead of the default 1000.
			ForceSendFields: []string{"Priority"},
		}

		op, err := client.InsertFirewallRule(ctx, project, rule)
		if err != nil {
			return names, fmt.Errorf("failed to insert deny-all egress firewall rule %q: %w", r.name, err)
		}
		names = append(names, r.name)
		if err := waitForOp(ctx, client, project, op); err != nil {
			return names, fmt.Errorf("deny-all egress firewall rule %q insert: %w", r.name, err)
		}
	}
	return names, nil
}

// RestoreEgressGCP deletes the deny-all egress firewall rules created by BlockEgressGCP
func RestoreEgressGCP(ctx context.Context, client ComputeAPI, project string, ruleNames []string) error {
	var errs []error
	for _, name := range ruleNames {
		op, err := client.DeleteFirewallRule(ctx, project, name)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to delete egress firewall rule %q: %w", name, err))
			continue
		}
		if err := waitForOp(ctx, client, project, op); err != nil {
			errs = append(errs, fmt.Errorf("egress firewall rule %q delete: %w", name, err))
		}
	}
	return errors.Join(errs...)
}
