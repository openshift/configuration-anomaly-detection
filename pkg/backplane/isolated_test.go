package backplane

import (
	"net"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetStringFieldFromJWT(t *testing.T) {
	// This is a valid JWT with {"email":"test@example.com","sub":"12345"} payload (unsigned)
	// Header: {"alg":"none","typ":"JWT"} → eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0
	// Payload: {"email":"test@example.com","sub":"12345","count":42} → eyJlbWFpbCI6InRlc3RAZXhhbXBsZS5jb20iLCJzdWIiOiIxMjM0NSIsImNvdW50Ijo0Mn0
	validToken := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJlbWFpbCI6InRlc3RAZXhhbXBsZS5jb20iLCJzdWIiOiIxMjM0NSIsImNvdW50Ijo0Mn0." //nolint:gosec // G101 false positive: unsigned test JWT with dummy data, not real credentials

	tests := []struct {
		name        string
		token       string
		field       string
		expected    string
		expectError bool
		errorMsg    string
	}{
		{
			name:     "extract email field",
			token:    validToken,
			field:    "email",
			expected: "test@example.com",
		},
		{
			name:     "extract sub field",
			token:    validToken,
			field:    "sub",
			expected: "12345",
		},
		{
			name:        "missing field",
			token:       validToken,
			field:       "nonexistent",
			expectError: true,
			errorMsg:    "no field nonexistent on given token",
		},
		{
			name:        "non-string field",
			token:       validToken,
			field:       "count",
			expectError: true,
			errorMsg:    "does not contain a string value",
		},
		{
			name:        "invalid token",
			token:       "not-a-jwt",
			field:       "email",
			expectError: true,
			errorMsg:    "failed to parse jwt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := getStringFieldFromJWT(tt.token, tt.field)
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestVerifyIPTrusted(t *testing.T) {
	trustedIPs := []string{
		"10.0.0.0/24",
		"192.168.1.0/24",
		"172.16.0.100/32",
	}

	tests := []struct {
		name        string
		ip          string
		expectError bool
	}{
		{
			name:        "IP in first range",
			ip:          "10.0.0.50",
			expectError: false,
		},
		{
			name:        "IP in second range",
			ip:          "192.168.1.200",
			expectError: false,
		},
		{
			name:        "exact /32 match",
			ip:          "172.16.0.100",
			expectError: false,
		},
		{
			name:        "IP outside all ranges",
			ip:          "8.8.8.8",
			expectError: true,
		},
		{
			name:        "IP just outside range",
			ip:          "10.0.1.1",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			require.NotNil(t, ip, "test IP must be valid")

			err := verifyIPTrusted(ip, trustedIPs)
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "is not in the trusted IP range")
			} else {
				assert.NoError(t, err)
			}
		})
	}

	t.Run("empty trusted list rejects all", func(t *testing.T) {
		err := verifyIPTrusted(net.ParseIP("10.0.0.1"), []string{})
		assert.Error(t, err)
	})
}

func TestGetTrustedIPInlinePolicy(t *testing.T) {
	ips := []string{"10.0.0.0/24", "192.168.1.0/24"}

	policy, err := getTrustedIPInlinePolicy(ips)
	require.NoError(t, err)
	require.NotEmpty(t, policy)

	// Verify it's valid JSON by checking key structural elements
	assert.Contains(t, policy, `"Version":"2012-10-17"`)
	assert.Contains(t, policy, `"Sid":"DenyNonRHProxy"`)
	assert.Contains(t, policy, `"Effect":"Deny"`)
	assert.Contains(t, policy, `"Sid":"AllowAll"`)
	assert.Contains(t, policy, `"Effect":"Allow"`)
	assert.Contains(t, policy, `"10.0.0.0/24"`)
	assert.Contains(t, policy, `"192.168.1.0/24"`)
	assert.Contains(t, policy, `"NotIpAddress"`)

	// Verify DenyNonRHProxy comes before AllowAll (deny-first ordering)
	denyIdx := len(policy) // fallback
	allowIdx := 0
	for i := range policy {
		if i+len(`"DenyNonRHProxy"`) <= len(policy) && policy[i:i+len(`"DenyNonRHProxy"`)] == `"DenyNonRHProxy"` {
			denyIdx = i
		}
		if i+len(`"AllowAll"`) <= len(policy) && policy[i:i+len(`"AllowAll"`)] == `"AllowAll"` {
			allowIdx = i
		}
	}
	assert.Less(t, denyIdx, allowIdx, "DenyNonRHProxy statement must come before AllowAll")
}

func TestBuildRoleSequence(t *testing.T) {
	t.Run("basic sequence with session policy ARN", func(t *testing.T) {
		resp := assumeChainResponse{
			AssumptionSequence: []namedRoleArn{
				{Name: "Jump-Role", Arn: "arn:aws:iam::111:role/Jump"},
				{Name: customerRoleArnName, Arn: "arn:aws:iam::222:role/Target"},
			},
			CustomerRoleSessionName: "cad-session",
			SessionPolicyArn:        "arn:aws:iam::aws:policy/MyPolicy",
			ExternalID:              "ext-123",
		}

		seq := buildRoleSequence(resp, "user@example.com", "")

		require.Len(t, seq, 2)

		// First role: Jump-Role — uses email as session name, no special policies
		assert.Equal(t, "Jump-Role", seq[0].Name)
		assert.Equal(t, "user@example.com", seq[0].RoleSessionName)
		assert.False(t, seq[0].IsCustomerRole)
		assert.Empty(t, seq[0].ExternalID)
		assert.Nil(t, seq[0].InlinePolicy)

		// Second role: Target-Role-Arn — uses customer session name, has policy ARN and external ID
		assert.Equal(t, customerRoleArnName, seq[1].Name)
		assert.Equal(t, "cad-session", seq[1].RoleSessionName)
		assert.True(t, seq[1].IsCustomerRole)
		assert.Equal(t, "ext-123", seq[1].ExternalID)
		require.Len(t, seq[1].PolicyARNs, 1)
		assert.Equal(t, "arn:aws:iam::aws:policy/MyPolicy", *seq[1].PolicyARNs[0].Arn)
		assert.Nil(t, seq[1].InlinePolicy)
	})

	t.Run("customer role with inline policy fallback", func(t *testing.T) {
		resp := assumeChainResponse{
			AssumptionSequence: []namedRoleArn{
				{Name: customerRoleArnName, Arn: "arn:aws:iam::222:role/Target"},
			},
			CustomerRoleSessionName: "cad-session",
			SessionPolicyArn:        "", // empty → should use inline policy
		}
		inlinePolicy := `{"Version":"2012-10-17","Statement":[]}`

		seq := buildRoleSequence(resp, "user@example.com", inlinePolicy)

		require.Len(t, seq, 1)
		assert.True(t, seq[0].IsCustomerRole)
		require.NotNil(t, seq[0].InlinePolicy)
		assert.Equal(t, inlinePolicy, *seq[0].InlinePolicy)
		assert.Empty(t, seq[0].PolicyARNs)
	})

	t.Run("org role gets customer session name and external ID", func(t *testing.T) {
		resp := assumeChainResponse{
			AssumptionSequence: []namedRoleArn{
				{Name: orgRoleArnName, Arn: "arn:aws:iam::333:role/OrgRole"},
			},
			CustomerRoleSessionName: "cad-session",
			ExternalID:              "ext-456",
		}

		seq := buildRoleSequence(resp, "user@example.com", "")

		require.Len(t, seq, 1)
		assert.Equal(t, "cad-session", seq[0].RoleSessionName)
		assert.Equal(t, "ext-456", seq[0].ExternalID)
		assert.False(t, seq[0].IsCustomerRole) // only Target-Role-Arn is marked as customer
	})

	t.Run("no external ID when not set", func(t *testing.T) {
		resp := assumeChainResponse{
			AssumptionSequence: []namedRoleArn{
				{Name: customerRoleArnName, Arn: "arn:aws:iam::222:role/Target"},
			},
			CustomerRoleSessionName: "cad-session",
			ExternalID:              "",
		}

		seq := buildRoleSequence(resp, "user@example.com", "")
		require.Len(t, seq, 1)
		assert.Empty(t, seq[0].ExternalID)
	})

	t.Run("session policy ARN takes priority over inline policy", func(t *testing.T) {
		resp := assumeChainResponse{
			AssumptionSequence: []namedRoleArn{
				{Name: customerRoleArnName, Arn: "arn:aws:iam::222:role/Target"},
			},
			CustomerRoleSessionName: "cad-session",
			SessionPolicyArn:        "arn:aws:iam::aws:policy/Managed",
		}

		seq := buildRoleSequence(resp, "user@example.com", `{"some":"inline-policy"}`)

		require.Len(t, seq, 1)
		assert.Nil(t, seq[0].InlinePolicy, "inline policy should NOT be set when SessionPolicyArn is present")
		require.Len(t, seq[0].PolicyARNs, 1)
		assert.Equal(t, "arn:aws:iam::aws:policy/Managed", *seq[0].PolicyARNs[0].Arn)
	})
}

func TestResolveProxyURL(t *testing.T) {
	tests := []struct {
		name     string
		awsProxy string
		bpProxy  string
		expected string
	}{
		{name: "aws proxy takes priority", awsProxy: "http://aws:8080", bpProxy: "http://bp:8080", expected: "http://aws:8080"},
		{name: "falls back to bp proxy", awsProxy: "", bpProxy: "http://bp:8080", expected: "http://bp:8080"},
		{name: "both empty", awsProxy: "", bpProxy: "", expected: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, resolveProxyURL(tt.awsProxy, tt.bpProxy))
		})
	}
}

func TestAssumeRoleSequence_EmptySequence(t *testing.T) {
	_, err := assumeRoleSequence(t.Context(), nil, []roleArnSession{}, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "role ARN sequence cannot be empty")
}

func TestIdentityTokenValue(t *testing.T) {
	token := identityTokenValue("my-jwt-token")
	bytes, err := token.GetIdentityToken()
	assert.NoError(t, err)
	assert.Equal(t, []byte("my-jwt-token"), bytes)
}

func TestRoleArnSessionPolicyARNsDefault(t *testing.T) {
	resp := assumeChainResponse{
		AssumptionSequence: []namedRoleArn{
			{Name: "Some-Role", Arn: "arn:aws:iam::111:role/SomeRole"},
		},
	}

	seq := buildRoleSequence(resp, "user@example.com", "")

	require.Len(t, seq, 1)
	// Non-customer roles should have an empty (non-nil) PolicyARNs slice
	assert.Equal(t, []ststypes.PolicyDescriptorType{}, seq[0].PolicyARNs)
	assert.Nil(t, seq[0].InlinePolicy)
}

func TestGetTrustedIPInlinePolicy_EmptyIPs(t *testing.T) {
	policy, err := getTrustedIPInlinePolicy([]string{})
	require.NoError(t, err)

	assert.Contains(t, policy, `"Version":"2012-10-17"`)
	assert.Contains(t, policy, `"DenyNonRHProxy"`)
	// SourceIp should be an empty array, not null
	assert.Contains(t, policy, `"aws:SourceIp":[]`)
}

func TestVerifyIPTrusted_InvalidCIDR(t *testing.T) {
	err := verifyIPTrusted(net.ParseIP("10.0.0.1"), []string{"not-a-cidr"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse trusted IP CIDR")
}

func TestHttpClientWithProxy(t *testing.T) {
	client := httpClientWithProxy("http://proxy:8080")
	assert.NotNil(t, client)
	assert.NotNil(t, client.Transport)
}

func TestStsClient(t *testing.T) {
	t.Run("without proxy", func(t *testing.T) {
		client, err := stsClient("")
		assert.NoError(t, err)
		assert.NotNil(t, client)
	})

	t.Run("with proxy", func(t *testing.T) {
		client, err := stsClient("http://proxy:8080")
		assert.NoError(t, err)
		assert.NotNil(t, client)
	})
}

func TestGetIsolatedAWSCredentials_EmptyClusterID(t *testing.T) {
	// Passing the zero-value cluster should fail at the ID check
	client := &ClientImpl{}
	_, err := client.GetIsolatedAWSCredentials(t.Context(), nil, "arn:aws:iam::123:role/Test", "")
	assert.Error(t, err)
}

func TestGetIsolatedAWSCredentials_EmptyInitialArn(t *testing.T) {
	client := &ClientImpl{}
	// Can't create a real cluster object easily, but we can test the nil path
	_, err := client.GetIsolatedAWSCredentials(t.Context(), nil, "", "")
	assert.Error(t, err)
}

// TestBuildRoleSequence_FullChain tests a realistic 3-step role chain
func TestBuildRoleSequence_FullChain(t *testing.T) {
	resp := assumeChainResponse{
		AssumptionSequence: []namedRoleArn{
			{Name: "SRE-Jump-Role", Arn: "arn:aws:iam::111:role/SRE-Jump"},
			{Name: orgRoleArnName, Arn: "arn:aws:iam::222:role/OrgRole"},
			{Name: customerRoleArnName, Arn: "arn:aws:iam::333:role/CustomerRole"},
		},
		CustomerRoleSessionName: "cad-remediation",
		SessionPolicyArn:        "arn:aws:iam::aws:policy/ScopedPolicy",
		ExternalID:              "ext-id-abc",
	}

	seq := buildRoleSequence(resp, "sre@redhat.com", `{"ignored":"because session arn is set"}`)

	require.Len(t, seq, 3)

	// Step 1: SRE Jump Role — email session, no special handling
	assert.Equal(t, "sre@redhat.com", seq[0].RoleSessionName)
	assert.Empty(t, seq[0].ExternalID)
	assert.False(t, seq[0].IsCustomerRole)

	// Step 2: Org Role — customer session name, external ID, not marked as customer
	assert.Equal(t, "cad-remediation", seq[1].RoleSessionName)
	assert.Equal(t, "ext-id-abc", seq[1].ExternalID)
	assert.False(t, seq[1].IsCustomerRole)

	// Step 3: Customer Role — customer session name, external ID, session policy ARN (not inline)
	assert.Equal(t, "cad-remediation", seq[2].RoleSessionName)
	assert.Equal(t, "ext-id-abc", seq[2].ExternalID)
	assert.True(t, seq[2].IsCustomerRole)
	assert.Nil(t, seq[2].InlinePolicy)
	require.Len(t, seq[2].PolicyARNs, 1)
	assert.Equal(t, aws.String("arn:aws:iam::aws:policy/ScopedPolicy"), seq[2].PolicyARNs[0].Arn)
}
