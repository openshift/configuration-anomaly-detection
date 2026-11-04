package utils

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"google.golang.org/api/compute/v1"
)

const (
	testProject = "test-project"
	testNetwork = "projects/test-project/global/networks/my-vpc"
)

type mockComputeAPI struct {
	insertFunc func(ctx context.Context, project string, rule *compute.Firewall) (*compute.Operation, error)
	deleteFunc func(ctx context.Context, project, name string) (*compute.Operation, error)
	waitFunc   func(ctx context.Context, project, operationName string) (*compute.Operation, error)
}

func (m *mockComputeAPI) InsertFirewallRule(ctx context.Context, project string, rule *compute.Firewall) (*compute.Operation, error) {
	return m.insertFunc(ctx, project, rule)
}

func (m *mockComputeAPI) DeleteFirewallRule(ctx context.Context, project, name string) (*compute.Operation, error) {
	return m.deleteFunc(ctx, project, name)
}

func (m *mockComputeAPI) WaitForGlobalOp(ctx context.Context, project, operationName string) (*compute.Operation, error) {
	return m.waitFunc(ctx, project, operationName)
}

func doneOp(name string) *compute.Operation {
	return &compute.Operation{Name: name, Status: "DONE"}
}

func pendingOp(name string) *compute.Operation {
	return &compute.Operation{Name: name, Status: "PENDING"}
}

func TestBlockEgressGCP(t *testing.T) {
	t.Run("creates IPv4 and IPv6 deny-all egress rules", func(t *testing.T) {
		var rules []*compute.Firewall
		var capturedProject string
		mock := &mockComputeAPI{
			insertFunc: func(ctx context.Context, project string, rule *compute.Firewall) (*compute.Operation, error) {
				capturedProject = project
				rules = append(rules, rule)
				return doneOp("op-insert-" + rule.Name), nil
			},
			waitFunc: func(ctx context.Context, project, operationName string) (*compute.Operation, error) {
				t.Fatal("waitFunc should not be called when operation is already DONE")
				return nil, fmt.Errorf("unreachable")
			},
		}

		ruleNames, err := BlockEgressGCP(context.Background(), mock, testProject, testNetwork)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if capturedProject != testProject {
			t.Errorf("expected project %q, got %q", testProject, capturedProject)
		}
		if len(ruleNames) != 2 {
			t.Fatalf("expected 2 rule names, got %d", len(ruleNames))
		}
		if !strings.HasPrefix(ruleNames[0], firewallRulePrefix) {
			t.Errorf("IPv4 rule name %q does not have prefix %q", ruleNames[0], firewallRulePrefix)
		}
		if !strings.HasSuffix(ruleNames[1], "-v6") {
			t.Errorf("IPv6 rule name %q does not have suffix %q", ruleNames[1], "-v6")
		}

		if len(rules) != 2 {
			t.Fatalf("expected 2 rules inserted, got %d", len(rules))
		}

		for _, rule := range rules {
			if rule.Direction != "EGRESS" {
				t.Errorf("expected direction EGRESS, got %q", rule.Direction)
			}
			if rule.Priority != 0 {
				t.Errorf("expected priority 0, got %d", rule.Priority)
			}
			if len(rule.Denied) != 1 || rule.Denied[0].IPProtocol != "all" {
				t.Errorf("expected deny all protocols, got %+v", rule.Denied)
			}
			if rule.Network != testNetwork {
				t.Errorf("expected network %q, got %q", testNetwork, rule.Network)
			}
			foundPriority := false
			for _, f := range rule.ForceSendFields {
				if f == "Priority" {
					foundPriority = true
					break
				}
			}
			if !foundPriority {
				t.Error("ForceSendFields must include \"Priority\" to ensure priority 0 is not omitted")
			}
		}

		v4 := rules[0]
		if len(v4.DestinationRanges) != 1 || v4.DestinationRanges[0] != "0.0.0.0/0" {
			t.Errorf("expected IPv4 destination 0.0.0.0/0, got %v", v4.DestinationRanges)
		}

		v6 := rules[1]
		if len(v6.DestinationRanges) != 1 || v6.DestinationRanges[0] != "::/0" {
			t.Errorf("expected IPv6 destination ::/0, got %v", v6.DestinationRanges)
		}
	})

	t.Run("waits for pending operation", func(t *testing.T) {
		waitCalls := 0
		mock := &mockComputeAPI{
			insertFunc: func(ctx context.Context, project string, rule *compute.Firewall) (*compute.Operation, error) {
				return pendingOp("op-insert"), nil
			},
			waitFunc: func(ctx context.Context, project, operationName string) (*compute.Operation, error) {
				waitCalls++
				// Alternate RUNNING then DONE for each rule
				if waitCalls%2 == 1 {
					return &compute.Operation{Name: operationName, Status: "RUNNING"}, nil
				}
				return doneOp(operationName), nil
			},
		}

		_, err := BlockEgressGCP(context.Background(), mock, testProject, testNetwork)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Two rules, each PENDING → RUNNING → DONE (2 waits each).
		if waitCalls != 4 {
			t.Errorf("expected 4 wait calls, got %d", waitCalls)
		}
	})

	t.Run("returns error on API failure", func(t *testing.T) {
		mock := &mockComputeAPI{
			insertFunc: func(ctx context.Context, project string, rule *compute.Firewall) (*compute.Operation, error) {
				return nil, fmt.Errorf("permission denied")
			},
		}

		_, err := BlockEgressGCP(context.Background(), mock, testProject, testNetwork)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "failed to insert deny-all egress firewall rule") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("returns error on operation failure", func(t *testing.T) {
		mock := &mockComputeAPI{
			insertFunc: func(ctx context.Context, project string, rule *compute.Firewall) (*compute.Operation, error) {
				return &compute.Operation{
					Name:   "op-fail",
					Status: "DONE",
					Error: &compute.OperationError{
						Errors: []*compute.OperationErrorErrors{
							{Code: "QUOTA_EXCEEDED", Message: "quota exceeded"},
						},
					},
				}, nil
			},
			waitFunc: func(ctx context.Context, project, operationName string) (*compute.Operation, error) {
				t.Fatal("waitFunc should not be called when operation is already DONE")
				return nil, fmt.Errorf("unreachable")
			},
		}

		_, err := BlockEgressGCP(context.Background(), mock, testProject, testNetwork)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "QUOTA_EXCEEDED") {
			t.Errorf("expected error to contain QUOTA_EXCEEDED, got: %v", err)
		}
	})

	t.Run("returns already-created names on partial failure", func(t *testing.T) {
		callCount := 0
		mock := &mockComputeAPI{
			insertFunc: func(ctx context.Context, project string, rule *compute.Firewall) (*compute.Operation, error) {
				callCount++
				if callCount == 2 {
					return nil, fmt.Errorf("quota exceeded")
				}
				return doneOp("op-insert"), nil
			},
			waitFunc: func(ctx context.Context, project, operationName string) (*compute.Operation, error) {
				t.Fatal("waitFunc should not be called when operation is already DONE")
				return nil, fmt.Errorf("unreachable")
			},
		}

		names, err := BlockEgressGCP(context.Background(), mock, testProject, testNetwork)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if len(names) != 1 {
			t.Errorf("expected 1 successfully created rule name, got %d", len(names))
		}
	})
}

func TestRestoreEgressGCP(t *testing.T) {
	t.Run("deletes all firewall rules", func(t *testing.T) {
		var capturedNames []string
		mock := &mockComputeAPI{
			deleteFunc: func(ctx context.Context, project, name string) (*compute.Operation, error) {
				capturedNames = append(capturedNames, name)
				return doneOp("op-delete-" + name), nil
			},
			waitFunc: func(ctx context.Context, project, operationName string) (*compute.Operation, error) {
				t.Fatal("waitFunc should not be called when operation is already DONE")
				return nil, fmt.Errorf("unreachable")
			},
		}

		ruleNames := []string{"cad-e2e-deny-egress-aabbccdd", "cad-e2e-deny-egress-aabbccdd-v6"}
		err := RestoreEgressGCP(context.Background(), mock, testProject, ruleNames)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(capturedNames) != 2 {
			t.Fatalf("expected 2 delete calls, got %d", len(capturedNames))
		}
		if !reflect.DeepEqual(capturedNames, ruleNames) {
			t.Errorf("expected deleted rules %v, got %v", ruleNames, capturedNames)
		}
	})

	t.Run("waits for pending operation", func(t *testing.T) {
		waitCalls := 0
		mock := &mockComputeAPI{
			deleteFunc: func(ctx context.Context, project, name string) (*compute.Operation, error) {
				return pendingOp("op-delete"), nil
			},
			waitFunc: func(ctx context.Context, project, operationName string) (*compute.Operation, error) {
				waitCalls++
				return doneOp("op-delete"), nil
			},
		}

		err := RestoreEgressGCP(context.Background(), mock, testProject, []string{"rule-1", "rule-2"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if waitCalls != 2 {
			t.Errorf("expected 2 wait calls, got %d", waitCalls)
		}
	})

	t.Run("returns error on API failure", func(t *testing.T) {
		mock := &mockComputeAPI{
			deleteFunc: func(ctx context.Context, project, name string) (*compute.Operation, error) {
				return nil, fmt.Errorf("not found")
			},
		}

		err := RestoreEgressGCP(context.Background(), mock, testProject, []string{"rule-1"})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "failed to delete egress firewall rule") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("collects errors from multiple rules", func(t *testing.T) {
		mock := &mockComputeAPI{
			deleteFunc: func(ctx context.Context, project, name string) (*compute.Operation, error) {
				return nil, fmt.Errorf("not found: %s", name)
			},
		}

		err := RestoreEgressGCP(context.Background(), mock, testProject, []string{"rule-1", "rule-2"})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "rule-1") || !strings.Contains(err.Error(), "rule-2") {
			t.Errorf("expected error to mention both rules, got: %v", err)
		}
	})

	t.Run("returns error on operation failure", func(t *testing.T) {
		mock := &mockComputeAPI{
			deleteFunc: func(ctx context.Context, project, name string) (*compute.Operation, error) {
				return &compute.Operation{
					Name:   "op-fail",
					Status: "DONE",
					Error: &compute.OperationError{
						Errors: []*compute.OperationErrorErrors{
							{Code: "RESOURCE_NOT_FOUND", Message: "rule not found"},
						},
					},
				}, nil
			},
			waitFunc: func(ctx context.Context, project, operationName string) (*compute.Operation, error) {
				t.Fatal("waitFunc should not be called when operation is already DONE")
				return nil, fmt.Errorf("unreachable")
			},
		}

		err := RestoreEgressGCP(context.Background(), mock, testProject, []string{"rule-1"})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "RESOURCE_NOT_FOUND") {
			t.Errorf("expected error to contain RESOURCE_NOT_FOUND, got: %v", err)
		}
	})
}
