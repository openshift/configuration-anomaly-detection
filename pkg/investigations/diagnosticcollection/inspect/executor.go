package inspect

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	k8sclient "github.com/openshift/configuration-anomaly-detection/pkg/k8s"
)

const (
	// DefaultTimeout is the default timeout for inspect commands
	DefaultTimeout = 5 * time.Minute
)

// Executor handles running `oc adm inspect` commands
type Executor struct {
	k8sClient k8sclient.Client
	timeout   time.Duration
}

// New creates a new inspect executor
func New(k8sClient k8sclient.Client) *Executor {
	return &Executor{
		k8sClient: k8sClient,
		timeout:   DefaultTimeout,
	}
}

// WithTimeout sets a custom timeout
func (e *Executor) WithTimeout(timeout time.Duration) *Executor {
	e.timeout = timeout
	return e
}

// Execute runs `oc adm inspect` for the specified resources
// Returns the directory path where diagnostic data was collected
func (e *Executor) Execute(resources []string) (string, error) {
	if len(resources) == 0 {
		return "", fmt.Errorf("no resources specified for inspection")
	}

	// Create temporary directory for inspect output
	destDir, err := os.MkdirTemp("", "cad-inspect-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}

	logging.Infof("Running oc adm inspect for resources: %v", resources)
	logging.Infof("Output directory: %s", destDir)

	// Build the oc adm inspect command
	args := []string{"adm", "inspect"}
	args = append(args, resources...)
	args = append(args, "--dest-dir", destDir)

	// Execute the command
	cmd := exec.Command("oc", args...)

	// Set timeout
	if e.timeout > 0 {
		go func() {
			time.Sleep(e.timeout)
			if cmd.Process != nil {
				logging.Warnf("oc adm inspect command timed out after %v, killing process", e.timeout)
				cmd.Process.Kill()
			}
		}()
	}

	// Run the command and capture output
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Clean up the directory on error
		os.RemoveAll(destDir)
		return "", fmt.Errorf("oc adm inspect failed: %w\nOutput: %s", err, string(output))
	}

	logging.Infof("oc adm inspect completed successfully")
	logging.Debugf("Output: %s", string(output))

	// Verify that the directory contains data
	if isEmpty, err := isDirEmpty(destDir); err != nil {
		os.RemoveAll(destDir)
		return "", fmt.Errorf("failed to check output directory: %w", err)
	} else if isEmpty {
		os.RemoveAll(destDir)
		return "", fmt.Errorf("oc adm inspect produced no output")
	}

	return destDir, nil
}

// Cleanup removes the inspect output directory
func (e *Executor) Cleanup(dir string) error {
	if dir == "" || !strings.HasPrefix(dir, os.TempDir()) {
		return fmt.Errorf("refusing to clean up directory that doesn't look like a temp dir: %s", dir)
	}

	logging.Debugf("Cleaning up inspect directory: %s", dir)
	return os.RemoveAll(dir)
}

// isDirEmpty checks if a directory is empty
func isDirEmpty(dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}
	return len(entries) == 0, nil
}

// GetResourceFiles returns all YAML files for a specific resource type
// For example, GetResourceFiles(dir, "clusterversion") returns ClusterVersion YAML files
func GetResourceFiles(inspectDir, resourceType string) ([]string, error) {
	var files []string

	err := filepath.Walk(inspectDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(path, ".yaml") {
			// Check if the path contains the resource type
			if strings.Contains(strings.ToLower(path), strings.ToLower(resourceType)) {
				files = append(files, path)
			}
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk directory: %w", err)
	}

	return files, nil
}
