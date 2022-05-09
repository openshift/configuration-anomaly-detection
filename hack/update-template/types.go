package main

// Template is the k8s template type. to keep dependencies minimal, k8s api is not pulled in
type Template struct {
	APIVersion string        `yaml:"apiVersion"`
	Kind       string        `yaml:"kind"`
	Metadata   Metadata      `yaml:"metadata"`
	Parameters []Parameter   `yaml:"parameters"`
	Objects    []interface{} `yaml:"objects"`
}

// Parameter is a parameter for the template. to keep dependencies minimal, k8s api is not pulled in
type Parameter struct {
	Name        string `yaml:"name"`
	DisplayName string `yaml:"displayName,omitempty"`
	Description string `yaml:"description"`
	Value       string `yaml:"value,omitempty"`
	Required    bool   `yaml:"required,omitempty"`
	Generate    string `yaml:"generate,omitempty"`
	From        string `yaml:"from,omitempty"`
}

// Metadata is the k8s metadata type. to keep dependencies minimal, k8s api is not pulled in
type Metadata struct {
	Name string `yaml:"name"`
}
