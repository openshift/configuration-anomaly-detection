package srelib

import (
	"fmt"
	"os/exec"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"

	"github.com/petrkotas/srelib/sdk"
	v1 "github.com/petrkotas/srelib/sdk/v1"
)

// PluginClient manages the lifecycle of the srelib plugin process.
type PluginClient struct {
	raw    *plugin.Client
	client v1.Client
}

// LaunchPlugin starts the srelib plugin binary and returns a connected client.
// The caller must call Close() when done.
func LaunchPlugin(pluginPath string, logger hclog.Logger) (*PluginClient, error) {
	raw := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig:  sdk.HandshakeConfig,
		VersionedPlugins: map[int]plugin.PluginSet{1: {"srelib": &v1.Plugin{}}},
		Cmd:              exec.Command(pluginPath),
		Logger:           logger,
		AllowedProtocols: []plugin.Protocol{plugin.ProtocolNetRPC},
	})

	rpcClient, err := raw.Client()
	if err != nil {
		raw.Kill()
		return nil, fmt.Errorf("failed to connect to srelib plugin: %w", err)
	}

	iface, err := rpcClient.Dispense("srelib")
	if err != nil {
		raw.Kill()
		return nil, fmt.Errorf("failed to dispense srelib client: %w", err)
	}

	client, ok := iface.(v1.Client)
	if !ok {
		raw.Kill()
		return nil, fmt.Errorf("unexpected type from srelib plugin: %T", iface)
	}

	return &PluginClient{raw: raw, client: client}, nil
}

// Client returns the underlying srelib v1.Client.
func (p *PluginClient) Client() v1.Client {
	return p.client
}

// Close kills the plugin process.
func (p *PluginClient) Close() {
	p.raw.Kill()
}
