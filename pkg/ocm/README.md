# OCM Package

Use the `ocm.New` to create an OCM client. It will provide functions to interact with OpenShift Cluster Manager (OCM) resources. The `ocm.New` receives the OCM configuration file as a parameter. If it is left blank, it will search for the config at the default position (`~/.ocm.json`, `/ocm/ocm.json`)

[embedmd]:# (../../cadctl/cmd/cluster-missing/cluster-missing.go /\/\/ GetOCMClient/ /^}$/)
```go
// GetOCMClient will retrieve the OcmClient from the 'ocm' package
func GetOCMClient() (ocm.OcmClient, error) {
	// in this case it's ok if the envvar is empty
	CAD_OCM_FILE_PATH := os.Getenv("CAD_OCM_FILE_PATH")
	return ocm.New(CAD_OCM_FILE_PATH)
}
```

## Testing

For testing, you can specify your ocm config in the New function, or leave the field blank.
