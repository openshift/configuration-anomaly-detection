package pullsecret

import (
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func createTestSecret(data string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      PullSecretName,
			Namespace: PullSecretNamespace,
		},
		Type: corev1.SecretTypeDockerConfigJson,
		Data: map[string][]byte{
			".dockerconfigjson": []byte(data),
		},
	}
}

func TestGetAuthEmail(t *testing.T) {
	tests := []struct {
		name          string
		secretData    string
		authKey       string
		expectedEmail string
		expectedError error
	}{
		{
			name:          "happy path - email extracted successfully",
			secretData:    `{"auths":{"cloud.openshift.com":{"auth":"TestAuthValue","email":"test_user@redhat.com"}}}`,
			authKey:       CloudOpenShiftComAuthKey,
			expectedEmail: "test_user@redhat.com",
			expectedError: nil,
		},
		{
			name:          "missing auth entry",
			secretData:    `{"auths":{"registry.redhat.io":{"auth":"TestToken","email":"test@example.com"}}}`,
			authKey:       CloudOpenShiftComAuthKey,
			expectedEmail: "",
			expectedError: &SecretAuthNotFoundError{Auth: CloudOpenShiftComAuthKey},
		},
		{
			name:          "empty email",
			secretData:    `{"auths":{"cloud.openshift.com":{"auth":"TestAuthValue","email":""}}}`,
			authKey:       CloudOpenShiftComAuthKey,
			expectedEmail: "",
			expectedError: &AuthEmailNotFoundError{Auth: CloudOpenShiftComAuthKey},
		},
		{
			name:          "no email field",
			secretData:    `{"auths":{"cloud.openshift.com":{"auth":"TestAuthValue"}}}`,
			authKey:       CloudOpenShiftComAuthKey,
			expectedEmail: "",
			expectedError: &AuthEmailNotFoundError{Auth: CloudOpenShiftComAuthKey},
		},
		{
			name:          "full pull secret with valid email",
			secretData:    `{"auths":{"950916221866.dkr.ecr.us-east-1.amazonaws.com":{"auth":"testTokenValue","email":""},"cloud.openshift.com":{"auth":"TestAuthValue","email":"test_fake_email@redhat.com"},"registry.redhat.io":{"auth":"TestPersonalTokenTwo","email":"test_fake_email@redhat.com"}}}`,
			authKey:       CloudOpenShiftComAuthKey,
			expectedEmail: "test_fake_email@redhat.com",
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := createTestSecret(tt.secretData)
			email, err := GetAuthEmail(secret, tt.authKey)

			if tt.expectedError != nil {
				if err == nil {
					t.Errorf("expected error %v but got none", tt.expectedError)
					return
				}
				// Check error type matches using errors.As
				var secretAuthErr *SecretAuthNotFoundError
				var authEmailErr *AuthEmailNotFoundError
				var expectedSecretAuthErr *SecretAuthNotFoundError
				var expectedAuthEmailErr *AuthEmailNotFoundError

				switch {
				case errors.As(tt.expectedError, &expectedSecretAuthErr):
					if !errors.As(err, &secretAuthErr) {
						t.Errorf("expected SecretAuthNotFoundError, got %T", err)
					}
				case errors.As(tt.expectedError, &expectedAuthEmailErr):
					if !errors.As(err, &authEmailErr) {
						t.Errorf("expected AuthEmailNotFoundError, got %T", err)
					}
				default:
					t.Errorf("unexpected expected error type: %T", tt.expectedError)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if email != tt.expectedEmail {
				t.Errorf("expected email %q, got %q", tt.expectedEmail, email)
			}
		})
	}
}

func TestGetAuthEmail_SecretErrors(t *testing.T) {
	tests := []struct {
		name          string
		secret        *corev1.Secret
		expectedError error
	}{
		{
			name: "empty secret data",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      PullSecretName,
					Namespace: PullSecretNamespace,
				},
				Data: nil,
			},
			expectedError: ErrSecretDataEmpty,
		},
		{
			name: "missing dockerconfigjson",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      PullSecretName,
					Namespace: PullSecretNamespace,
				},
				Data: map[string][]byte{
					"wrong-key": []byte("{}"),
				},
			},
			expectedError: ErrSecretMissingDockerConfigJson,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetAuthEmail(tt.secret, CloudOpenShiftComAuthKey)

			if !errors.Is(err, tt.expectedError) {
				t.Errorf("expected error %v, got %v", tt.expectedError, err)
			}
		})
	}
}

func TestValidateEmailWithSecret(t *testing.T) {
	tests := []struct {
		name            string
		secretData      string
		ocmEmail        string
		expectedValid   bool
		expectedWarning string
	}{
		{
			name:            "email matches",
			secretData:      `{"auths":{"cloud.openshift.com":{"auth":"TestAuthValue","email":"test@redhat.com"}}}`,
			ocmEmail:        "test@redhat.com",
			expectedValid:   true,
			expectedWarning: "",
		},
		{
			name:            "email mismatch",
			secretData:      `{"auths":{"cloud.openshift.com":{"auth":"TestAuthValue","email":"cluster@redhat.com"}}}`,
			ocmEmail:        "ocm@redhat.com",
			expectedValid:   false,
			expectedWarning: "Pull secret does not match on cluster and in OCM",
		},
		{
			name:            "missing cloud.openshift.com",
			secretData:      `{"auths":{"registry.redhat.io":{"auth":"TestAuthValue","email":"test@redhat.com"}}}`,
			ocmEmail:        "test@redhat.com",
			expectedValid:   false,
			expectedWarning: "not found in cluster pull secret",
		},
		{
			name:            "empty email in pull secret",
			secretData:      `{"auths":{"cloud.openshift.com":{"auth":"TestAuthValue","email":""}}}`,
			ocmEmail:        "test@redhat.com",
			expectedValid:   false,
			expectedWarning: "email is empty in cluster pull secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := createTestSecret(tt.secretData)
			result := ValidateEmailWithSecret(secret, tt.ocmEmail)

			if result.IsValid != tt.expectedValid {
				t.Errorf("expected IsValid=%v, got %v", tt.expectedValid, result.IsValid)
			}

			if tt.expectedWarning != "" {
				if len(result.Warnings) == 0 {
					t.Errorf("expected warning containing %q, got no warnings", tt.expectedWarning)
				} else {
					found := false
					for _, w := range result.Warnings {
						if strings.Contains(w, tt.expectedWarning) {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("expected warning containing %q, got %v", tt.expectedWarning, result.Warnings)
					}
				}
			}

			if tt.expectedWarning == "" && len(result.Warnings) > 0 {
				t.Errorf("expected no warnings, got %v", result.Warnings)
			}
		})
	}
}

func TestValidateEmail(t *testing.T) {
	tests := []struct {
		name          string
		secretData    string
		ocmEmail      string
		expectedValid bool
	}{
		{
			name:          "valid - emails match",
			secretData:    `{"auths":{"cloud.openshift.com":{"auth":"TestAuthValue","email":"test@redhat.com"}}}`,
			ocmEmail:      "test@redhat.com",
			expectedValid: true,
		},
		{
			name:          "invalid - emails don't match",
			secretData:    `{"auths":{"cloud.openshift.com":{"auth":"TestAuthValue","email":"cluster@redhat.com"}}}`,
			ocmEmail:      "ocm@redhat.com",
			expectedValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := createTestSecret(tt.secretData)
			k8scli := fake.NewClientBuilder().WithObjects(secret).Build()

			result := ValidateEmail(k8scli, tt.ocmEmail)

			if result.IsValid != tt.expectedValid {
				t.Errorf("expected IsValid=%v, got %v (warnings: %v)", tt.expectedValid, result.IsValid, result.Warnings)
			}
		})
	}
}
