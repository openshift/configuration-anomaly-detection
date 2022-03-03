# OCM Package

Use the `ocm.New` to create an OCM client. It will provide functions to interact with OpenShift Cluster Manager (OCM) resources. The `ocm.New` receives the OCM configuration file as a parameter. If it is left blank, it will search for the config at the default position (`~/.ocm.json`, `/ocm/ocm.json`)

```go
_, err := ocm.New("./ocm.json")
if err != nil {
    return fmt.Errorf("could not create ocm client: %w", err)
}
cd, err := ocm.GetClusterDeployment("01234567890123456")
if err != nil {
    return fmt.Errorf("could not get clusterDeployment: %w", err)
}
```

## Testing

For testing, you can specify your ocm config in the New function, or leave the field blank. 