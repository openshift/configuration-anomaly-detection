package pullsecret

import (
	"errors"
	"fmt"
)

var ErrSecretMissingDockerConfigJson = errors.New("secret missing '.dockerconfigjson'")

var ErrSecretDataEmpty = errors.New("pull secret data is empty")

type SecretAuthNotFoundError struct {
	Auth string
}

func (e *SecretAuthNotFoundError) Error() string {
	return fmt.Sprintf("auth '%s' not found in pull secret", e.Auth)
}

type AuthEmailNotFoundError struct {
	Auth string
}

func (e *AuthEmailNotFoundError) Error() string {
	return fmt.Sprintf("email is empty for auth '%s'", e.Auth)
}

type ParseSecretError struct {
	Err error
}

func (e *ParseSecretError) Error() string {
	return fmt.Sprintf("failed to parse pull secret: %v", e.Err)
}

func (e *ParseSecretError) Unwrap() error {
	return e.Err
}
