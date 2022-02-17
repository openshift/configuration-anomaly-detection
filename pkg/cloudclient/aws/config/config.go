package config

// Config is a representation of the config stored in the cloud-config configmap
type Config struct {
	JumpRole       string `yaml:"jump-role"`
	CredentialsDir string `yaml:"credentials-dir"`
}
