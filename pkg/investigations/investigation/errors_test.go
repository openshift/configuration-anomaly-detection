package investigation

import (
	"errors"
	"fmt"
	"testing"
)

func TestInfrastructureError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      InfrastructureError
		expected string
	}{
		{
			name: "with context and underlying error",
			err: InfrastructureError{
				Context: "AWS API call",
				Err:     errors.New("connection timeout"),
			},
			expected: "infrastructure error (AWS API call): connection timeout",
		},
		{
			name: "without context",
			err: InfrastructureError{
				Context: "",
				Err:     errors.New("connection timeout"),
			},
			expected: "infrastructure error: connection timeout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("InfrastructureError.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestInfrastructureError_Unwrap(t *testing.T) {
	underlying := errors.New("underlying error")
	err := InfrastructureError{
		Context: "test",
		Err:     underlying,
	}

	unwrapped := err.Unwrap()
	// We intentionally compare pointers here to verify Unwrap returns the exact error
	if !errors.Is(unwrapped, underlying) {
		t.Errorf("InfrastructureError.Unwrap() = %v, want %v", unwrapped, underlying)
	}
}

func TestFindingError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      FindingError
		expected string
	}{
		{
			name: "with context and underlying error",
			err: FindingError{
				Context: "CloudTrail data too old",
				Err:     errors.New("data older than 90 days"),
			},
			expected: "investigation finding (CloudTrail data too old): data older than 90 days",
		},
		{
			name: "with underlying error only",
			err: FindingError{
				Context: "",
				Err:     errors.New("data older than 90 days"),
			},
			expected: "investigation finding: data older than 90 days",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("FindingError.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestFindingError_Unwrap(t *testing.T) {
	underlying := errors.New("underlying error")
	err := FindingError{
		Context: "test",
		Err:     underlying,
	}

	unwrapped := err.Unwrap()
	// We intentionally compare pointers here to verify Unwrap returns the exact error
	if !errors.Is(unwrapped, underlying) {
		t.Errorf("FindingError.Unwrap() = %v, want %v", unwrapped, underlying)
	}
}

func TestWrapInfrastructure(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		context string
		wantNil bool
	}{
		{
			name:    "nil error returns nil",
			err:     nil,
			context: "test context",
			wantNil: true,
		},
		{
			name:    "non-nil error returns InfrastructureError",
			err:     errors.New("test error"),
			context: "test context",
			wantNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WrapInfrastructure(tt.err, tt.context)
			if tt.wantNil {
				if got != nil {
					t.Errorf("WrapInfrastructure() = %v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Error("WrapInfrastructure() = nil, want non-nil")
				return
			}
			var infraErr InfrastructureError
			if !errors.As(got, &infraErr) {
				t.Errorf("WrapInfrastructure() type = %T, want InfrastructureError", got)
				return
			}
			if infraErr.Context != tt.context {
				t.Errorf("InfrastructureError.Context = %q, want %q", infraErr.Context, tt.context)
			}
			if !errors.Is(infraErr.Err, tt.err) {
				t.Errorf("InfrastructureError.Err = %v, want %v", infraErr.Err, tt.err)
			}
		})
	}
}

func TestWrapFinding(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		context string
		wantNil bool
	}{
		{
			name:    "nil error returns nil",
			err:     nil,
			context: "test context",
			wantNil: true,
		},
		{
			name:    "non-nil error returns FindingError",
			err:     errors.New("test error"),
			context: "test context",
			wantNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WrapFinding(tt.err, tt.context)
			if tt.wantNil {
				if got != nil {
					t.Errorf("WrapFinding() = %v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Error("WrapFinding() = nil, want non-nil")
				return
			}
			var findingErr FindingError
			if !errors.As(got, &findingErr) {
				t.Errorf("WrapFinding() type = %T, want FindingError", got)
				return
			}
			if findingErr.Context != tt.context {
				t.Errorf("FindingError.Context = %q, want %q", findingErr.Context, tt.context)
			}
			if !errors.Is(findingErr.Err, tt.err) {
				t.Errorf("FindingError.Err = %v, want %v", findingErr.Err, tt.err)
			}
		})
	}
}

func TestIsInfrastructureError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "direct InfrastructureError",
			err:  InfrastructureError{Context: "test", Err: errors.New("test")},
			want: true,
		},
		{
			name: "wrapped InfrastructureError",
			err:  fmt.Errorf("wrapped: %w", InfrastructureError{Context: "test", Err: errors.New("test")}),
			want: true,
		},
		{
			name: "regular error",
			err:  errors.New("regular error"),
			want: false,
		},
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "FindingError",
			err:  FindingError{Context: "test", Err: errors.New("test")},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsInfrastructureError(tt.err); got != tt.want {
				t.Errorf("IsInfrastructureError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsFindingError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "direct FindingError",
			err:  FindingError{Context: "test", Err: errors.New("test")},
			want: true,
		},
		{
			name: "wrapped FindingError",
			err:  fmt.Errorf("wrapped: %w", FindingError{Context: "test", Err: errors.New("test")}),
			want: true,
		},
		{
			name: "regular error",
			err:  errors.New("regular error"),
			want: false,
		},
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "InfrastructureError",
			err:  InfrastructureError{Context: "test", Err: errors.New("test")},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsFindingError(tt.err); got != tt.want {
				t.Errorf("IsFindingError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExistingErrorTypes_Unwrap(t *testing.T) {
	underlying := errors.New("underlying error")

	tests := []struct {
		name string
		err  error
	}{
		{
			name: "ClusterNotFoundError",
			err:  ClusterNotFoundError{ClusterID: "test", Err: underlying},
		},
		{
			name: "ClusterDeploymentNotFoundError",
			err:  ClusterDeploymentNotFoundError{ClusterID: "test", Err: underlying},
		},
		{
			name: "AWSClientError",
			err:  AWSClientError{ClusterID: "test", Err: underlying},
		},
		{
			name: "RestConfigError",
			err:  RestConfigError{ClusterID: "test", Err: underlying},
		},
		{
			name: "OCClientError",
			err:  OCClientError{ClusterID: "test", Err: underlying},
		},
		{
			name: "K8SClientError",
			err:  K8SClientError{ClusterID: "test", Err: underlying},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !errors.Is(tt.err, underlying) {
				t.Errorf("%s: errors.Is() should find the underlying error", tt.name)
			}
		})
	}
}
