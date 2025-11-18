package oc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

type Client interface {
	CreateMustGather(additionalFlags []string) error
	Clean() error
}

type clientImpl struct {
	kubeConfigFile        string
	cleanupKubeConfigFile func() error
}

// New creates a new OC Client with the given rest.Config.
func New(ctx context.Context, config *rest.Config) (Client, error) {
	kubeConfigFile, cleanupKubeConfigFile, err := createKubeconfigFileForRestConfig(ctx, config)
	if err != nil {
		return nil, err
	}
	return &clientImpl{
		kubeConfigFile:        kubeConfigFile,
		cleanupKubeConfigFile: cleanupKubeConfigFile,
	}, nil
}

func (c *clientImpl) Clean() error {
	return c.cleanupKubeConfigFile()
}

func (c *clientImpl) CreateMustGather(additionalFlags []string) error {
	// Handle sigints and sigterms
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-signalChan
		fmt.Println("Received interrupt signal, canceling operation...")
		cancel()
	}()

	cmdArgs := []string{"adm", "must-gather", "--kubeconfig=" + c.kubeConfigFile}
	cmdArgs = append(cmdArgs, additionalFlags...)

	//nolint:gosec
	cmd := exec.CommandContext(ctx, "oc", cmdArgs...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = io.MultiWriter(os.Stderr, &stderr)

	err := cmd.Run()
	if err != nil {
		if errors.Is(ctx.Err(), context.Canceled) {
			return fmt.Errorf("command was canceled by user (e.g., Ctrl+C): %w", err)
		}
		return fmt.Errorf("failed to run 'oc adm must-gather': %w\nstderr: %s", err, stderr.String())
	}

	return nil
}

func createKubeconfigFileForRestConfig(ctx context.Context, restConfig *rest.Config) (string, func() error, error) {
	var proxyUrlString string

	if restConfig.Proxy != nil {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.com", nil)
		if err != nil {
			return "", nil, err
		}
		proxyUrl, err := restConfig.Proxy(req)
		if err != nil {
			return "", nil, err
		}
		if proxyUrl != nil {
			proxyUrlString = proxyUrl.String()
		}
	}

	clusters := make(map[string]*clientcmdapi.Cluster)
	clusters["default-cluster"] = &clientcmdapi.Cluster{
		Server:                   restConfig.Host,
		CertificateAuthorityData: restConfig.CAData,
		ProxyURL:                 proxyUrlString,
	}

	contexts := make(map[string]*clientcmdapi.Context)
	contexts["default-context"] = &clientcmdapi.Context{
		Cluster:  "default-cluster",
		AuthInfo: "default-user",
	}

	authinfos := make(map[string]*clientcmdapi.AuthInfo)
	authinfos["default-user"] = &clientcmdapi.AuthInfo{
		ClientCertificateData: restConfig.CertData,
		ClientKeyData:         restConfig.KeyData,
		Impersonate:           restConfig.Impersonate.UserName,
		Token:                 restConfig.BearerToken,
	}

	val, ok := restConfig.Impersonate.Extra["reason"]
	if ok {
		impersonateUserExtra := make(map[string][]string)
		impersonateUserExtra["reason"] = val
		authinfos["default-user"].ImpersonateUserExtra = impersonateUserExtra
	}

	clientConfig := clientcmdapi.Config{
		Kind:           "Config",
		APIVersion:     "v1",
		Clusters:       clusters,
		Contexts:       contexts,
		CurrentContext: "default-context",
		AuthInfos:      authinfos,
	}

	kubeConfigFile, err := os.CreateTemp("", "kubeconfig")
	if err != nil {
		return "", nil, err
	}
	err = kubeConfigFile.Close()
	if err != nil {
		return "", nil, err
	}

	cleanup := func() error {
		return os.Remove(kubeConfigFile.Name())
	}
	if err := clientcmd.WriteToFile(clientConfig, kubeConfigFile.Name()); err != nil {
		if cleanupErr := cleanup(); cleanupErr != nil {
			return "", nil, fmt.Errorf("failed to write kubeconfig (cleanup also failed: %w): %w", cleanupErr, err)
		}
		return "", nil, fmt.Errorf("failed to write kubeconfig: %w", err)
	}

	return kubeConfigFile.Name(), cleanup, nil
}
