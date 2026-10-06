package backplane

// This file contains the implementation of the isolated backplane access flow.
// mainly copied from https://github.com/openshift/backplane-cli/blob/main/cmd/ocm-backplane/cloud/common.go

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awscreds "github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/golang-jwt/jwt/v4"
	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
)

const (
	oldFlowSupportRole = "role/RH-Technical-Support-Access"

	assumeRoleMaxRetries   = 3
	assumeRoleRetryBackoff = 5 * time.Second

	policyVersion    = "2012-10-17"
	defaultAWSRegion = "us-east-1"

	customerRoleArnName = "Target-Role-Arn"
	orgRoleArnName      = "Org-Role-Arn"
)

// assumeChainResponse is the response from the backplane API's GetAssumeRoleSequence endpoint
type assumeChainResponse struct {
	AssumptionSequence      []namedRoleArn `json:"assumptionSequence"`
	CustomerRoleSessionName string         `json:"customerRoleSessionName"`
	SessionPolicyArn        string         `json:"sessionPolicyArn"`
	ExternalID              string         `json:"externalId,omitempty"`
}

type namedRoleArn struct {
	Name string `json:"name"`
	Arn  string `json:"arn"`
}

// roleArnSession is one step in a chained AssumeRole sequence
type roleArnSession struct {
	Name            string
	RoleSessionName string
	RoleArn         string
	IsCustomerRole  bool
	InlinePolicy    *string
	PolicyARNs      []ststypes.PolicyDescriptorType
	ExternalID      string
}

// policyDocument represents an IAM policy document
type policyDocument struct {
	Version   string            `json:"Version"`
	Statement []policyStatement `json:"Statement"`
}

type policyStatement struct {
	Sid       string            `json:"Sid"`
	Effect    string            `json:"Effect"`
	Action    []string          `json:"Action"`
	Principal map[string]string `json:",omitempty"`
	Resource  *string           `json:",omitempty"`
	Condition *policyCondition  `json:",omitempty"`
}

type policyCondition struct {
	NotIpAddress ipAddress `json:"NotIpAddress"`
}

type ipAddress struct {
	SourceIp []string `json:"aws:SourceIp"`
}

// IsIsolatedBackplaneAccess determines if a cluster uses isolated backplane access.
// HCP clusters always use isolated access. STS clusters use it if their
// support jump role doesn't match the old-flow format.
func IsIsolatedBackplaneAccess(cluster *cmv1.Cluster, ocmClient ocm.Client) (bool, error) {
	baseDomain := cluster.DNS().BaseDomain()
	if strings.HasSuffix(baseDomain, "devshiftusgov.com") || strings.HasSuffix(baseDomain, "openshiftusgov.com") {
		return false, nil
	}

	if cluster.Hypershift().Enabled() {
		return true, nil
	}

	if cluster.AWS().STS().Enabled() {
		resp, err := ocmClient.GetConnection().ClustersMgmt().V1().Clusters().Cluster(cluster.ID()).StsSupportJumpRole().Get().Send()
		if err != nil {
			return false, fmt.Errorf("failed to get sts support jump role ARN for cluster %v: %w", cluster.ID(), err)
		}
		roleArn := resp.Body().RoleArn()
		// New-style roles use a unique suffix (e.g., RH-Technical-Support-123456);
		// old-style roles end with RH-Technical-Support-Access.
		return !strings.HasSuffix(roleArn, oldFlowSupportRole), nil
	}

	return false, nil
}

// GetIsolatedAWSCredentials retrieves AWS credentials for a cluster that uses isolated backplane access.
// This implements the client-side JWT assume-role chain flow.
func (c *ClientImpl) GetIsolatedAWSCredentials(ctx context.Context, cluster *cmv1.Cluster, initialArn string, awsProxyURL string) (*AWSCredentials, error) {
	if cluster.ID() == "" {
		return nil, fmt.Errorf("must provide non-empty cluster ID")
	}

	ocmConnection := c.ocmClient.GetConnection()
	ocmToken, _, err := ocmConnection.TokensContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to get token for ocm connection: %w", err)
	}

	email, err := getStringFieldFromJWT(ocmToken, "email")
	if err != nil {
		return nil, fmt.Errorf("unable to extract email from given token: %w", err)
	}

	if initialArn == "" {
		return nil, fmt.Errorf("initialArn is required for isolated backplane access; set BACKPLANE_INITIAL_ARN")
	}

	// Determine proxy to use for STS operations
	stsProxyURL := resolveProxyURL(awsProxyURL, c.proxyURL)

	// Step 1: Assume initial role with JWT
	initialClient, err := stsClient(stsProxyURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create sts client: %w", err)
	}

	seedCredentials, err := assumeRoleWithJWT(ocmToken, initialArn, initialClient)
	if err != nil {
		return nil, fmt.Errorf("failed to assume role using JWT: %w", err)
	}

	// Step 2: Verify STS connection with seed credentials
	seedConfig := aws.Config{
		Region:      defaultAWSRegion,
		Credentials: awscreds.NewStaticCredentialsProvider(seedCredentials.AccessKeyID, seedCredentials.SecretAccessKey, seedCredentials.SessionToken),
	}
	if stsProxyURL != "" {
		seedConfig.HTTPClient = httpClientWithProxy(stsProxyURL)
	}
	seedStsClient := sts.NewFromConfig(seedConfig)
	if _, err := seedStsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); err != nil {
		return nil, fmt.Errorf("unable to verify STS connection (GetCallerIdentity failed): %w", err)
	}

	// Step 3: Get assume role sequence from backplane API
	response, err := c.bpClient.GetAssumeRoleSequenceWithResponse(ctx, cluster.ID())
	if err != nil {
		return nil, fmt.Errorf("failed to fetch arn sequence: %w", err)
	}
	if response.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch arn sequence: status %d", response.StatusCode())
	}

	var roleChainResp assumeChainResponse
	if err := json.Unmarshal(response.Body, &roleChainResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal assume role sequence response: %w", err)
	}

	// Step 4: Verify trusted IPs and build inline policy
	inlinePolicy, err := c.verifyTrustedIPAndGetPolicy(ctx, stsProxyURL)
	if err != nil {
		return nil, err
	}

	// Step 5: Build the assume role sequence
	roleSequence := buildRoleSequence(roleChainResp, email, inlinePolicy)

	// Step 6: Execute assume role chain
	seedClient := sts.NewFromConfig(aws.Config{
		Region:      defaultAWSRegion,
		Credentials: awscreds.NewStaticCredentialsProvider(seedCredentials.AccessKeyID, seedCredentials.SecretAccessKey, seedCredentials.SessionToken),
	})

	targetCredentials, err := assumeRoleSequence(ctx, seedClient, roleSequence, stsProxyURL)
	if err != nil {
		return nil, fmt.Errorf("failed to assume role sequence: %w", err)
	}

	return &AWSCredentials{
		AccessKeyID:     targetCredentials.AccessKeyID,
		SecretAccessKey: targetCredentials.SecretAccessKey,
		SessionToken:    targetCredentials.SessionToken,
		Expiration:      targetCredentials.Expires.String(),
		Region:          cluster.Region().ID(),
	}, nil
}

func resolveProxyURL(awsProxy, backplaneProxy string) string {
	if awsProxy != "" {
		return awsProxy
	}
	return backplaneProxy
}

func stsClient(proxyURL string) (*sts.Client, error) {
	cfg := aws.Config{Region: defaultAWSRegion}
	if proxyURL != "" {
		cfg.HTTPClient = httpClientWithProxy(proxyURL)
	}
	return sts.NewFromConfig(cfg), nil
}

func httpClientWithProxy(proxyURL string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) {
				return url.Parse(proxyURL)
			},
		},
	}
}

// getStringFieldFromJWT extracts a string field from a JWT token without verification.
func getStringFieldFromJWT(token string, field string) (string, error) {
	parser := new(jwt.Parser)
	jwtToken, _, err := parser.ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return "", fmt.Errorf("failed to parse jwt: %w", err)
	}
	claims, ok := jwtToken.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("failed to extract claims from jwt")
	}
	claim, ok := claims[field]
	if !ok {
		return "", fmt.Errorf("no field %v on given token", field)
	}
	claimString, ok := claim.(string)
	if !ok {
		return "", fmt.Errorf("field %v does not contain a string value", field)
	}
	return claimString, nil
}

// identityTokenValue wraps a string to satisfy the stscreds.IdentityTokenRetriever interface
type identityTokenValue string

func (j identityTokenValue) GetIdentityToken() ([]byte, error) {
	return []byte(j), nil
}

// assumeRoleWithJWT exchanges a JWT for temporary AWS credentials via STS AssumeRoleWithWebIdentity
func assumeRoleWithJWT(jwtToken string, roleArn string, stsClient stscreds.AssumeRoleWithWebIdentityAPIClient) (aws.Credentials, error) {
	email, err := getStringFieldFromJWT(jwtToken, "email")
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("unable to extract email from given token: %w", err)
	}

	credentialsCache := aws.NewCredentialsCache(stscreds.NewWebIdentityRoleProvider(
		stsClient,
		roleArn,
		identityTokenValue(jwtToken),
		func(options *stscreds.WebIdentityRoleOptions) {
			options.RoleSessionName = email
			options.Duration = 60 * time.Minute
		},
	))

	result, err := credentialsCache.Retrieve(context.TODO())
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("unable to assume the given role with the token provided: %w", err)
	}
	return result, nil
}

// buildRoleSequence constructs the ordered role assumption steps from the backplane API response
func buildRoleSequence(resp assumeChainResponse, email string, inlinePolicy string) []roleArnSession {
	sequence := make([]roleArnSession, 0, len(resp.AssumptionSequence))
	for _, entry := range resp.AssumptionSequence {
		session := roleArnSession{
			Name:    entry.Name,
			RoleArn: entry.Arn,
		}

		if entry.Name == customerRoleArnName || entry.Name == orgRoleArnName {
			session.RoleSessionName = resp.CustomerRoleSessionName
		} else {
			session.RoleSessionName = email
		}

		session.PolicyARNs = []ststypes.PolicyDescriptorType{}
		if entry.Name == customerRoleArnName {
			session.IsCustomerRole = true
			if resp.SessionPolicyArn != "" {
				session.PolicyARNs = []ststypes.PolicyDescriptorType{
					{Arn: aws.String(resp.SessionPolicyArn)},
				}
			} else if inlinePolicy != "" {
				session.InlinePolicy = &inlinePolicy
			}
		}

		if resp.ExternalID != "" && (entry.Name == orgRoleArnName || entry.Name == customerRoleArnName) {
			session.ExternalID = resp.ExternalID
		}

		sequence = append(sequence, session)
	}
	return sequence
}

// assumeRoleSequence chains through multiple AssumeRole calls
func assumeRoleSequence(ctx context.Context, seedClient stscreds.AssumeRoleAPIClient, sequence []roleArnSession, proxyURL string) (aws.Credentials, error) {
	if len(sequence) == 0 {
		return aws.Credentials{}, fmt.Errorf("role ARN sequence cannot be empty")
	}

	nextClient := seedClient
	var lastCredentials aws.Credentials

	for i, session := range sequence {
		result, err := assumeRole(ctx, nextClient, session)
		retryCount := 0
		for err != nil {
			if retryCount < assumeRoleMaxRetries {
				time.Sleep(assumeRoleRetryBackoff)
				nextClient, err = createAssumeRoleSequenceClient(lastCredentials, proxyURL)
				if err != nil {
					return aws.Credentials{}, fmt.Errorf("failed to create client with credentials for role %q: %w", session.Name, err)
				}
				result, err = assumeRole(ctx, nextClient, session)
				retryCount++
			} else {
				return aws.Credentials{}, fmt.Errorf("failed to assume role %q after %d retries: %w", session.Name, assumeRoleMaxRetries, err)
			}
		}
		lastCredentials = result

		if i < len(sequence)-1 {
			nextClient, err = createAssumeRoleSequenceClient(lastCredentials, proxyURL)
			if err != nil {
				return aws.Credentials{}, fmt.Errorf("failed to create client for role %q: %w", session.Name, err)
			}
		}
	}

	return lastCredentials, nil
}

func assumeRole(ctx context.Context, client stscreds.AssumeRoleAPIClient, session roleArnSession) (aws.Credentials, error) {
	provider := stscreds.NewAssumeRoleProvider(client, session.RoleArn, func(options *stscreds.AssumeRoleOptions) {
		options.RoleSessionName = session.RoleSessionName
		options.Duration = 60 * time.Minute
		if session.InlinePolicy != nil {
			options.Policy = session.InlinePolicy
		}
		if len(session.PolicyARNs) > 0 {
			options.PolicyARNs = session.PolicyARNs
		}
		if session.ExternalID != "" {
			options.ExternalID = aws.String(session.ExternalID)
		}
	})
	result, err := provider.Retrieve(ctx)
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("failed to assume role %q: %w", session.Name, err)
	}
	return result, nil
}

func createAssumeRoleSequenceClient(creds aws.Credentials, proxyURL string) (stscreds.AssumeRoleAPIClient, error) {
	opts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithCredentialsProvider(awscreds.NewStaticCredentialsProvider(creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken)),
		awsconfig.WithRegion(defaultAWSRegion),
	}
	if proxyURL != "" {
		opts = append(opts, awsconfig.WithHTTPClient(httpClientWithProxy(proxyURL)))
	}
	cfg, err := awsconfig.LoadDefaultConfig(context.TODO(), opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}
	return sts.NewFromConfig(cfg), nil
}

// verifyTrustedIPAndGetPolicy checks the client egress IP against OCM's trusted IP list
// and builds an IAM inline policy restricting access to those IPs.
func (c *ClientImpl) verifyTrustedIPAndGetPolicy(ctx context.Context, proxyURL string) (string, error) {
	var httpClient *http.Client
	if proxyURL != "" {
		httpClient = httpClientWithProxy(proxyURL)
	} else {
		httpClient = &http.Client{}
	}

	clientIP, err := checkEgressIP(ctx, httpClient, "https://checkip.amazonaws.com/")
	if err != nil {
		return "", fmt.Errorf("failed to determine client IP: %w", err)
	}

	trustedIPs, err := c.getTrustedIPList(ctx)
	if err != nil {
		return "", err
	}

	if err := verifyIPTrusted(clientIP, trustedIPs); err != nil {
		return "", err
	}

	return getTrustedIPInlinePolicy(trustedIPs)
}

func checkEgressIP(ctx context.Context, client *http.Client, checkURL string) (net.IP, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, checkURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch IP: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	ip := net.ParseIP(strings.TrimSpace(string(body)))
	if ip == nil {
		return nil, fmt.Errorf("failed to parse IP %s", body)
	}
	return ip, nil
}

// getTrustedIPList fetches the trusted IP list from OCM and filters to IPs relevant for CAD.
func (c *ClientImpl) getTrustedIPList(ctx context.Context) ([]string, error) {
	conn := c.ocmClient.GetConnection()
	resp, err := conn.ClustersMgmt().V1().TrustedIPAddresses().List().Send()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch trusted IP list: %w", err)
	}

	var sourceIPList []string
	resp.Items().Each(func(ip *cmv1.TrustedIp) bool {
		if !ip.Enabled() {
			return true
		}
		id := ip.ID()
		// Filter to IPs expected to access customer AWS accounts.
		// Proxy IPs
		if strings.HasPrefix(id, "209.") ||
			strings.HasPrefix(id, "182.") ||
			strings.HasPrefix(id, "66.") ||
			strings.HasPrefix(id, "91.") {
			sourceIPList = append(sourceIPList, fmt.Sprintf("%s/32", id))
		}
		// CAD stage IPs
		if strings.HasPrefix(id, "3.216") ||
			strings.HasPrefix(id, "34.227") ||
			strings.HasPrefix(id, "98.85") {
			sourceIPList = append(sourceIPList, fmt.Sprintf("%s/32", id))
		}
		// CAD Prod IPs
		if strings.HasPrefix(id, "34.193") ||
			strings.HasPrefix(id, "52.203") ||
			strings.HasPrefix(id, "54.145") {
			sourceIPList = append(sourceIPList, fmt.Sprintf("%s/32", id))
		}
		// ROSA Boundary (SRE ECS Fargate) IPs
		if strings.HasPrefix(id, "54.243") {
			sourceIPList = append(sourceIPList, fmt.Sprintf("%s/32", id))
		}
		return true
	})
	return sourceIPList, nil
}

func verifyIPTrusted(ip net.IP, trustedIPs []string) error {
	for _, cidr := range trustedIPs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("failed to parse trusted IP CIDR %s: %w", cidr, err)
		}
		if network.Contains(ip) {
			return nil
		}
	}
	return fmt.Errorf("client IP %s is not in the trusted IP range", ip)
}

func getTrustedIPInlinePolicy(trustedIPs []string) (string, error) {
	policy := policyDocument{
		Version: policyVersion,
		Statement: []policyStatement{
			{
				Sid:      "DenyNonRHProxy",
				Effect:   "Deny",
				Action:   []string{"*"},
				Resource: aws.String("*"),
				Condition: &policyCondition{
					NotIpAddress: ipAddress{SourceIp: trustedIPs},
				},
			},
			{
				Sid:      "AllowAll",
				Effect:   "Allow",
				Action:   []string{"*"},
				Resource: aws.String("*"),
			},
		},
	}
	policyBytes, err := json.Marshal(policy)
	if err != nil {
		return "", fmt.Errorf("failed to marshal trusted IP inline policy: %w", err)
	}
	return string(policyBytes), nil
}
