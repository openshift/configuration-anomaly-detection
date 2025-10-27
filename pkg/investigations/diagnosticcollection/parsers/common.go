package parsers

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"sigs.k8s.io/yaml"
)

// ReadYAMLFile reads a YAML file and unmarshals it into the provided structure
func ReadYAMLFile(path string, out interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %w", path, err)
	}

	if err := yaml.Unmarshal(data, out); err != nil {
		return fmt.Errorf("failed to unmarshal YAML from %s: %w", path, err)
	}

	return nil
}

// FindYAMLFiles finds all YAML files in a directory (recursively)
func FindYAMLFiles(dir string) ([]string, error) {
	var yamlFiles []string

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && (strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml")) {
			yamlFiles = append(yamlFiles, path)
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk directory %s: %w", dir, err)
	}

	return yamlFiles, nil
}

// FindYAMLFilesByPattern finds YAML files matching a specific pattern in their path
// For example, pattern "clusterversion" will match files in paths containing "clusterversion"
func FindYAMLFilesByPattern(dir, pattern string) ([]string, error) {
	allFiles, err := FindYAMLFiles(dir)
	if err != nil {
		return nil, err
	}

	var matched []string
	for _, file := range allFiles {
		if strings.Contains(strings.ToLower(file), strings.ToLower(pattern)) {
			matched = append(matched, file)
		}
	}

	return matched, nil
}
