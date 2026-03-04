// Package pullsecret provides pull secret validation functionality
// This package validates cluster pull secrets against OCM account data,
// similar to osdctl's validate-pull-secret-ext command.
package pullsecret

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	sdk "github.com/openshift-online/ocm-sdk-go"
	v1 "github.com/openshift-online/ocm-sdk-go/accountsmgmt/v1"
	corev1 "k8s.io/api/core/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	PullSecretName           = "pull-secret"
	PullSecretNamespace      = "openshift-config" // #nosec G101
	CloudOpenShiftComAuthKey = "cloud.openshift.com"
)

type ValidationResult struct {
	IsValid  bool
	Warnings []string
}

func (v *ValidationResult) AddWarning(format string, args ...any) {
	v.Warnings = append(v.Warnings, fmt.Sprintf(format, args...))
}

type RegistryValidationResult struct {
	Registry     string
	EmailMatch   bool
	TokenMatch   bool
	EmailCluster string
	Error        error
}

// GetPullSecret retrieves the pull secret from the cluster
func GetPullSecret(k8scli client.Client) (*corev1.Secret, error) {
	secret := &corev1.Secret{}
	err := k8scli.Get(context.TODO(), k8stypes.NamespacedName{
		Namespace: PullSecretNamespace,
		Name:      PullSecretName,
	}, secret)
	if err != nil {
		return nil, err
	}
	return secret, nil
}

// GetAuthEmail extracts the email from a specific auth entry in the pull secret
func GetAuthEmail(secret *corev1.Secret, authKey string) (string, error) {
	if secret.Data == nil {
		return "", ErrSecretDataEmpty
	}

	dockerConfigJsonBytes, found := secret.Data[".dockerconfigjson"]
	if !found {
		return "", ErrSecretMissingDockerConfigJson
	}

	dockerConfigJson, err := v1.UnmarshalAccessToken(dockerConfigJsonBytes)
	if err != nil {
		return "", &ParseSecretError{Err: err}
	}

	auth, found := dockerConfigJson.Auths()[authKey]
	if !found {
		return "", &SecretAuthNotFoundError{Auth: authKey}
	}

	email := auth.Email()
	if email == "" {
		return "", &AuthEmailNotFoundError{Auth: authKey}
	}

	return email, nil
}

// ValidateEmailWithSecret compares the email in the pull secret against the OCM account email
func ValidateEmailWithSecret(secret *corev1.Secret, ocmEmail string) *ValidationResult {
	result := &ValidationResult{IsValid: true}

	clusterEmail, err := GetAuthEmail(secret, CloudOpenShiftComAuthKey)
	if err != nil {
		result.IsValid = false
		var secretAuthErr *SecretAuthNotFoundError
		var authEmailErr *AuthEmailNotFoundError
		var parseErr *ParseSecretError
		switch {
		case errors.As(err, &secretAuthErr):
			result.AddWarning("%s not found in cluster pull secret. This indicates the pull secret may be misconfigured.", secretAuthErr.Auth)
		case errors.As(err, &authEmailErr):
			result.AddWarning("%s email is empty in cluster pull secret. This indicates the pull secret may be misconfigured.", authEmailErr.Auth)
		case errors.As(err, &parseErr):
			result.AddWarning("Failed to parse pull secret: %v", parseErr.Err)
		case errors.Is(err, ErrSecretDataEmpty):
			result.AddWarning("Cluster pull secret Data is empty.")
		case errors.Is(err, ErrSecretMissingDockerConfigJson):
			result.AddWarning("Cluster pull secret does not contain the necessary .dockerconfigjson")
		default:
			result.AddWarning("Error reading pull secret: %v", err)
		}
		return result
	}

	if clusterEmail != ocmEmail {
		result.IsValid = false
		result.AddWarning("Pull secret does not match on cluster and in OCM.")
	}

	return result
}

// ValidateEmail validates the pull secret email against the OCM account email
func ValidateEmail(k8scli client.Client, ocmEmail string) *ValidationResult {
	secret, err := GetPullSecret(k8scli)
	if err != nil {
		result := &ValidationResult{IsValid: false}
		result.AddWarning("Failed to get pull secret from cluster: %v", err)
		return result
	}
	return ValidateEmailWithSecret(secret, ocmEmail)
}

// ValidateRegistryCredentials validates the cluster pull secret against OCM registry credentials
func ValidateRegistryCredentials(k8scli client.Client, ocmConn *sdk.Connection, accountID string, ocmEmail string) (*ValidationResult, []RegistryValidationResult) {
	result := &ValidationResult{IsValid: true}

	// Get the pull secret from the cluster
	secret, err := GetPullSecret(k8scli)
	if err != nil {
		result.IsValid = false
		result.AddWarning("Failed to get pull secret from cluster: %v", err)
		return result, nil
	}

	// get credentials from OCM
	registryCredentials, err := getOCMRegistryCredentials(ocmConn, accountID)
	if err != nil {
		result.IsValid = false
		result.AddWarning("Failed to get registry credentials from OCM: %v", err)
		return result, nil
	}

	if len(registryCredentials) == 0 {
		result.AddWarning("No registry credentials found in OCM for this account")
		return result, nil
	}

	registryResults := make([]RegistryValidationResult, 0, len(registryCredentials))

	dockerConfigJsonBytes, found := secret.Data[".dockerconfigjson"]
	if !found {
		result.IsValid = false
		result.AddWarning("Cluster pull secret does not contain the necessary .dockerconfigjson")
		return result, nil
	}

	dockerConfigJson, err := v1.UnmarshalAccessToken(dockerConfigJsonBytes)
	if err != nil {
		result.IsValid = false
		result.AddWarning("Failed to parse pull secret: %v", err)
		return result, nil
	}

	// Check each registry credential
	for _, regCred := range registryCredentials {
		regResult := RegistryValidationResult{}

		reg := regCred.Registry()
		if reg == nil {
			regResult.Error = fmt.Errorf("registry credential has no associated registry")
			registryResults = append(registryResults, regResult)
			result.IsValid = false
			result.AddWarning("Registry credential has no associated registry")
			continue
		}

		registryID := reg.ID()
		registry, err := getRegistryFromOCM(ocmConn, registryID)
		if err != nil {
			regResult.Registry = registryID
			regResult.Error = fmt.Errorf("failed to fetch registry from OCM: %w", err)
			registryResults = append(registryResults, regResult)
			result.IsValid = false
			result.AddWarning("Failed to fetch registry '%s' from OCM: %v", registryID, err)
			continue
		}

		regName := registry.Name()
		if regName == "" {
			regResult.Registry = registryID
			regResult.Error = fmt.Errorf("empty registry name from OCM")
			registryResults = append(registryResults, regResult)
			result.IsValid = false
			result.AddWarning("Empty registry name for registry ID '%s'", registryID)
			continue
		}

		regResult.Registry = regName

		// Find the matching auth entry in the cluster pull secret
		secretAuth, found := dockerConfigJson.Auths()[regName]
		if !found {
			regResult.Error = &SecretAuthNotFoundError{Auth: regName}
			registryResults = append(registryResults, regResult)
			result.IsValid = false
			result.AddWarning("Registry '%s' not found in cluster pull secret", regName)
			continue
		}

		// Check email match
		regResult.EmailCluster = secretAuth.Email()
		if ocmEmail != regResult.EmailCluster {
			regResult.EmailMatch = false
			result.IsValid = false
			result.AddWarning("Pull secret auth['%s'].email does not match OCM account email", regName)
		} else {
			regResult.EmailMatch = true
		}

		// Check token match
		// OCM stores; username and token separately
		// Cluster stores; base64(username:token) in the auth field
		ocmToken := regCred.Token()
		ocmUsername := regCred.Username()
		if ocmToken == "" || ocmUsername == "" {
			regResult.Error = fmt.Errorf("empty token or username in OCM registry credential")
			registryResults = append(registryResults, regResult)
			result.IsValid = false
			result.AddWarning("Empty token or username in OCM for registry '%s'", regName)
			continue
		}

		expectedToken := fmt.Sprintf("%s:%s", ocmUsername, ocmToken)
		clusterTokenB64 := secretAuth.Auth()
		clusterTokenBytes, err := base64.StdEncoding.DecodeString(clusterTokenB64)
		if err != nil {
			regResult.TokenMatch = false
			regResult.Error = fmt.Errorf("failed to decode cluster token: %w", err)
			registryResults = append(registryResults, regResult)
			result.IsValid = false
			result.AddWarning("Failed to decode token in cluster pull secret for registry '%s'", regName)
			continue
		}

		if string(clusterTokenBytes) != expectedToken {
			regResult.TokenMatch = false
			result.IsValid = false
			result.AddWarning("Registry credential token for '%s' does not match between cluster and OCM", regName)
		} else {
			regResult.TokenMatch = true
		}

		registryResults = append(registryResults, regResult)
	}

	return result, registryResults
}

// getOCMRegistryCredentials fetches registry credentials for an account from OCM
func getOCMRegistryCredentials(ocmConn *sdk.Connection, accountID string) ([]*v1.RegistryCredential, error) {
	searchString := fmt.Sprintf("account_id = '%s'", accountID)
	response, err := ocmConn.AccountsMgmt().V1().RegistryCredentials().List().Search(searchString).Send()
	if err != nil {
		return nil, err
	}
	return response.Items().Slice(), nil
}

// getRegistryFromOCM fetches registry details from OCM
func getRegistryFromOCM(ocmConn *sdk.Connection, registryID string) (*v1.Registry, error) {
	response, err := ocmConn.AccountsMgmt().V1().Registries().Registry(registryID).Get().Send()
	if err != nil {
		return nil, err
	}
	registry, ok := response.GetBody()
	if !ok {
		return nil, fmt.Errorf("empty response body for registry '%s'", registryID)
	}
	return registry, nil
}
