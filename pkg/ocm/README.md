# OCM Package

Use the `ocm.New` to create an OCM client. It will provide functions to interact with OpenShift Cluster Manager (OCM) resources. The `ocm.New` receives the OCM configuration file as a parameter. If it is left blank, it will search for the config at the default position (`~/.ocm.json`, `/ocm/ocm.json`)

[embedmd]:# (../../cadctl/cmd/investigate/investigate.go /\/\/ GetOCMClient/ /^}$/)
```go
// GetOCMClient will retrieve the OcmClient from the 'ocm' package
func GetOCMClient() (*ocm.SdkClient, error) {
	cadOcmFilePath := os.Getenv("CAD_OCM_FILE_PATH")

	_, err := os.Stat(cadOcmFilePath)
	if os.IsNotExist(err) {
		configDir, err := os.UserConfigDir()
		if err != nil {
			return nil, err
		}
		cadOcmFilePath = filepath.Join(configDir, "/ocm/ocm.json")
	}

	return ocm.New(cadOcmFilePath)
}
```

## Testing

For testing, you can specify your OCM config in the New function, or leave the field blank.
