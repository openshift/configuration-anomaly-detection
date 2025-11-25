package k8sclient

import (
	"bytes"
	"context"
	"fmt"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

// ExecInPod executes a command in a specific container within a pod and returns stdout
func ExecInPod(ctx context.Context, restConfig *rest.Config, pod *corev1.Pod, containerName string, command []string) ([]byte, error) {
	// Create a Kubernetes clientset
	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes clientset: %w", err)
	}

	// Prepare the API request
	req := clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(pod.Name).
		Namespace(pod.Namespace).
		SubResource("exec")

	// Set up the exec options
	execOptions := &corev1.PodExecOptions{
		Container: containerName,
		Command:   command,
		Stdout:    true,
		Stderr:    true,
		Stdin:     false,
		TTY:       false,
	}

	req.VersionedParams(execOptions, scheme.ParameterCodec)

	// Create the executor
	exec, err := remotecommand.NewSPDYExecutor(restConfig, "POST", req.URL())
	if err != nil {
		return nil, fmt.Errorf("failed to create SPDY executor: %w", err)
	}

	// Buffers to capture stdout and stderr
	var stdout, stderr bytes.Buffer

	// Execute the command
	err = exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
		Tty:    false,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to execute command in pod: %w (stderr: %s)", err, stderr.String())
	}

	return stdout.Bytes(), nil
}

// GetRestConfig extracts the rest.Config from our Client interface
// This is a helper to access the underlying config for exec operations
func GetRestConfig(k8sClient Client) (*rest.Config, error) {
	// Type assert to get the underlying clientImpl
	clientImpl, ok := k8sClient.(clientImpl)
	if !ok {
		return nil, fmt.Errorf("k8s client is not of expected type")
	}

	return clientImpl.restConfig, nil
}
