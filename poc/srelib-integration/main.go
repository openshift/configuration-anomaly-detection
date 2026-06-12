// POC: Using srelib inside configuration-anomaly-detection.
//
// This demonstrates how to:
//  1. Launch the srelib plugin process
//  2. Wrap its client behind CAD's ocm.Client interface via the Adapter
//  3. Use it in CAD's investigation resource builder
//
// To run for real you need the srelib plugin binary built:
//
//	cd ../srelib && go build -o srelib-plugin ./cmd/plugin
//	SRELIB_PLUGIN_PATH=../srelib/srelib-plugin go run ./poc/srelib-integration
package main

import (
	"fmt"
	"os"

	"github.com/hashicorp/go-hclog"

	cadocm "github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/srelib"
)

func main() {
	pluginPath := os.Getenv("SRELIB_PLUGIN_PATH")
	if pluginPath == "" {
		pluginPath = "srelib-plugin"
	}

	logger := hclog.New(&hclog.LoggerOptions{
		Name:  "cad-srelib-poc",
		Level: hclog.Info,
	})

	fmt.Println("=== CAD + srelib POC ===")
	fmt.Printf("Launching srelib plugin from: %s\n", pluginPath)

	pc, err := srelib.LaunchPlugin(pluginPath, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to launch plugin: %v\n", err)
		fmt.Println("\nTo build the plugin binary:")
		fmt.Println("  cd ../srelib && go build -o srelib-plugin ./cmd/plugin")
		os.Exit(1)
	}
	defer pc.Close()

	// Wrap the srelib client behind CAD's ocm.Client interface.
	var ocmClient cadocm.Client = srelib.NewAdapter(pc.Client())

	// Now use it exactly as CAD would — e.g. fetch cluster info.
	clusterID := os.Getenv("CLUSTER_ID")
	if clusterID == "" {
		clusterID = "my-test-cluster"
	}

	fmt.Printf("\nLooking up cluster: %s\n", clusterID)
	cluster, err := ocmClient.GetClusterInfo(clusterID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "GetClusterInfo failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Cluster ID:   %s\n", cluster.ID())
	fmt.Printf("Cluster Name: %s\n", cluster.Name())
	fmt.Printf("State:        %s\n", cluster.State())

	// Demonstrate getting the support role ARN via the same interface.
	arn, err := ocmClient.GetSupportRoleARN(cluster.ID())
	if err != nil {
		fmt.Fprintf(os.Stderr, "GetSupportRoleARN failed: %v\n", err)
	} else {
		fmt.Printf("Support ARN:  %s\n", arn)
	}

	fmt.Println("\n=== POC complete ===")
}
