package ocm

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	sdk "github.com/openshift-online/ocm-sdk-go"
)

// Config is the type used to store the configuration of the client.
// There's no way to line-split or predefine tags, so...
//
//nolint:lll
type Config struct {
	// TODO(efried): Better docs for things like AccessToken
	// TODO(efried): Dedup with flag docs in cmd/ocm/login/cmd.go:init where possible
	AccessToken  string   `json:"access_token,omitempty" doc:"Bearer access token."`
	ClientID     string   `json:"client_id,omitempty" doc:"OpenID client identifier."`
	ClientSecret string   `json:"client_secret,omitempty" doc:"OpenID client secret."`
	Insecure     bool     `json:"insecure,omitempty" doc:"Enables insecure communication with the server. This disables verification of TLS certificates and host names."`
	Password     string   `json:"password,omitempty" doc:"User password."`
	RefreshToken string   `json:"refresh_token,omitempty" doc:"Offline or refresh token."`
	Scopes       []string `json:"scopes,omitempty" doc:"OpenID scope. If this option is used it will replace completely the default scopes. Can be repeated multiple times to specify multiple scopes."`
	TokenURL     string   `json:"token_url,omitempty" doc:"OpenID token URL."`
	URL          string   `json:"url,omitempty" doc:"URL of the API gateway. The value can be the complete URL or an alias. The valid aliases are 'production', 'staging' and 'integration'."`
	User         string   `json:"user,omitempty" doc:"User name."`
	Pager        string   `json:"pager,omitempty" doc:"Pager command, for example 'less'. If empty no pager will be used."`
}

// Load loads the configuration from the configuration file. If the configuration file doesn't exist
// it will return an empty configuration object.
func Load() (cfg *Config, err error) {
	file, err := Location()
	if err != nil {
		return
	}
	_, err = os.Stat(file)
	if os.IsNotExist(err) {
		cfg = &Config{}
		return
	}
	if err != nil {
		err = fmt.Errorf("can't check if config file '%s' exists: %v", file, err)
		return
	}
	// #nosec G304
	data, err := os.ReadFile(file)
	if err != nil {
		err = fmt.Errorf("can't read config file '%s': %v", file, err)
		return
	}
	cfg = &Config{}
	if len(data) == 0 {
		return
	}
	err = json.Unmarshal(data, cfg)
	if err != nil {
		err = fmt.Errorf("can't parse config file '%s': %v", file, err)
		return
	}
	return
}

// Location returns the location of the configuration file. If a configuration file
// already exists in the HOME directory, it uses that, otherwise it prefers to
// use the XDG config directory.
func Location() (path string, err error) {
	if ocmconfig := os.Getenv("OCM_CONFIG"); ocmconfig != "" {
		return ocmconfig, nil
	}

	// Determine home directory to use for the legacy file path
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	path = filepath.Join(home, ".ocm.json")

	_, err = os.Stat(path)
	if os.IsNotExist(err) {
		// Determine standard config directory
		configDir, err := os.UserConfigDir()
		if err != nil {
			return path, err
		}

		// Use standard config directory
		path = filepath.Join(configDir, "/ocm/ocm.json")
	}

	return path, nil
}

// Connection creates a connection using this configuration.
func (c *Config) Connection() (connection *sdk.Connection, err error) {
	// Prepare the builder for the connection adding only the properties that have explicit
	// values in the configuration, so that default values won't be overridden:
	builder := sdk.NewConnectionBuilder()
	if c.TokenURL != "" {
		builder.TokenURL(c.TokenURL)
	}
	if c.ClientID != "" || c.ClientSecret != "" {
		builder.Client(c.ClientID, c.ClientSecret)
	}
	if c.Scopes != nil {
		builder.Scopes(c.Scopes...)
	}
	if c.URL != "" {
		builder.URL(c.URL)
	}
	if c.User != "" || c.Password != "" {
		builder.User(c.User, c.Password)
	}
	tokens := make([]string, 0, 2)
	if c.AccessToken != "" {
		tokens = append(tokens, c.AccessToken)
	}
	if c.RefreshToken != "" {
		tokens = append(tokens, c.RefreshToken)
	}
	if len(tokens) > 0 {
		builder.Tokens(tokens...)
	}
	builder.Insecure(c.Insecure)

	// Create the connection:
	connection, err = builder.Build()
	if err != nil {
		return
	}

	return
}
