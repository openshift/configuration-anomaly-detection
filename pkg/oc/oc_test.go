package oc

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func getMockRestConfig() *rest.Config {
	return &rest.Config{
		Host: "https://example.com",
		TLSClientConfig: rest.TLSClientConfig{
			CAFile:   "/path/to/ca.crt",
			CertFile: "/path/to/cert.crt",
			KeyFile:  "/path/to/key.key",
		},
		BearerToken: "some-token",
		Impersonate: rest.ImpersonationConfig{
			UserName: "testuser",
			Extra:    map[string][]string{"reason": {"test"}},
		},
		Proxy: func(req *http.Request) (*url.URL, error) {
			return url.Parse("http://proxy.example.com")
		},
	}
}

func TestCreateKubeconfigFileForRestConfig_Success(t *testing.T) {
	mockConfig := getMockRestConfig()

	// Create a tmp kubeconfig & delete after we're done
	kubeConfigFile, cleanup, err := createKubeconfigFileForRestConfig(context.Background(), mockConfig)
	assert.NoError(t, err)
	defer func() {
		err := cleanup()
		if err != nil {
			t.Logf("error cleaning up kubeconfig file: %v", err)
		}
	}()
	defer func() {
		err = os.Remove(kubeConfigFile)
		assert.NoError(t, err)
	}()

	_, err = os.Stat(kubeConfigFile)
	assert.NoError(t, err)

	config, err := clientcmd.LoadFromFile(kubeConfigFile)
	assert.NoError(t, err)

	cluster, ok := config.Clusters["default-cluster"]
	assert.True(t, ok)
	assert.Equal(t, mockConfig.Host, cluster.Server)

	assert.Equal(t, "http://proxy.example.com", cluster.ProxyURL)

	configContext, ok := config.Contexts["default-context"]
	assert.True(t, ok)
	assert.Equal(t, "default-cluster", configContext.Cluster)
	assert.Equal(t, "default-user", configContext.AuthInfo)

	authInfo, ok := config.AuthInfos["default-user"]
	assert.True(t, ok)
	assert.Equal(t, mockConfig.BearerToken, authInfo.Token)
	assert.Equal(t, "testuser", authInfo.Impersonate)
	assert.Equal(t, map[string][]string{"reason": {"test"}}, authInfo.ImpersonateUserExtra)
}
