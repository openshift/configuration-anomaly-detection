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

type LogCapture struct {
	buffer bytes.Buffer
}

func (capture *LogCapture) GetStdOut() string {
	return capture.buffer.String()
}

func (capture *LogCapture) Write(p []byte) (n int, err error) {
	a := string(p)
	capture.buffer.WriteString(a)
	return len(p), nil
}

// ExecInPod executes a command in a specific container within a pod and returns stdout
func ExecInPod(ctx context.Context, restConfig *rest.Config, pod *corev1.Pod, containerName string, command []string) (string, error) {
	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return "", fmt.Errorf("failed to create kubernetes clientset: %w", err)
	}

	req := clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(pod.Name).
		Namespace(pod.Namespace).
		SubResource("exec")

	execOptions := &corev1.PodExecOptions{
		Container: containerName,
		Command:   command,
		Stdout:    true,
		Stderr:    true,
		Stdin:     false,
		TTY:       false,
	}

	req.VersionedParams(execOptions, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(restConfig, "POST", req.URL())
	if err != nil {
		return "", fmt.Errorf("failed to create SPDY executor: %w", err)
	}

	capture := &LogCapture{}
	errorCapture := &LogCapture{}

	err = exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: capture,
		Stderr: errorCapture,
		Tty:    false,
	})
	if err != nil {
		return "", fmt.Errorf("failed to execute command in pod: %w", err)
	}

	cmdOutput := capture.GetStdOut()
	return cmdOutput, nil
}

// GetRestConfig extracts the rest.Config from our Client interface
// This is a helper to access the underlying config for exec operations
func GetRestConfig(k8sClient Client) (*rest.Config, error) {
	clientImpl, ok := k8sClient.(clientImpl)
	if !ok {
		return nil, fmt.Errorf("k8s client is not of expected type")
	}

	return clientImpl.restConfig, nil
}
