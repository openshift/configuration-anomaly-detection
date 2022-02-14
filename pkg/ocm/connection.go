package ocm

import (
	"fmt"

	ocmcfg "github.com/openshift-online/ocm-cli/pkg/config"
	sdk "github.com/openshift-online/ocm-sdk-go"
)

// ConnectionBuilder contains the information and logic needed to build a connection to OCM. Don't
// create instances of this type directly; use the NewConnection function instead.
type ConnectionBuilder struct {
	cfg              *ocmcfg.Config
	logger           *sdk.Logger
	transportWrapper sdk.TransportWrapper
}

// NewConnection creates a builder that can then be used to configure and build an OCM connection.
// Don't create instances of this type directly; use the NewConnection function instead.
func NewConnection() *ConnectionBuilder {
	return &ConnectionBuilder{}
}

// Build uses the information stored in the builder to create a new OCM connection.
func (b *ConnectionBuilder) Build() (result *sdk.Connection, err error) {
	if b.cfg == nil {
		// Load the configuration file:
		b.cfg, err = ocmcfg.Load()
		if err != nil {
			err = fmt.Errorf("Failed to load config file: %v", err)
			return result, err
		}
		if b.cfg == nil {
			err = fmt.Errorf("Not logged in, run the 'login' command")
			return result, err
		}
	}

	// Check that the configuration has credentials or tokens that haven't have expired:
	armed, _, err := b.cfg.Armed()
	if err != nil {
		return result, fmt.Errorf("Can't check if tokens have expired: %v", err)
	}
	if !armed {
		return result, fmt.Errorf("Tokens have expired, run the 'login' command")
	}

	builder := sdk.NewConnectionBuilder()
	if b.logger != nil {
		builder.Logger(*b.logger)
	}
	if b.transportWrapper != nil {
		builder.TransportWrapper(b.transportWrapper)
	}
	if b.cfg.TokenURL != "" {
		builder.TokenURL(b.cfg.TokenURL)
	}
	if b.cfg.ClientID != "" || b.cfg.ClientSecret != "" {
		builder.Client(b.cfg.ClientID, b.cfg.ClientSecret)
	}
	if b.cfg.Scopes != nil {
		builder.Scopes(b.cfg.Scopes...)
	}
	if b.cfg.URL != "" {
		builder.URL(b.cfg.URL)
	}
	if b.cfg.User != "" || b.cfg.Password != "" {
		builder.User(b.cfg.User, b.cfg.Password)
	}
	if b.cfg.AccessToken != "" {
		builder.Tokens(b.cfg.AccessToken)
	}
	if b.cfg.RefreshToken != "" {
		builder.Tokens(b.cfg.RefreshToken)
	}
	builder.Insecure(b.cfg.Insecure)

	// Create the connection:
	result, err = builder.Build()
	if err != nil {
		return result, fmt.Errorf("Can't create connection: %v", err)
	}

	return result, nil
}

func (b *ConnectionBuilder) Logger(logger *sdk.Logger) *ConnectionBuilder {
	b.logger = logger
	return b
}

func (b *ConnectionBuilder) TransportWrapper(wrapper sdk.TransportWrapper) *ConnectionBuilder {
	b.transportWrapper = wrapper
	return b
}
