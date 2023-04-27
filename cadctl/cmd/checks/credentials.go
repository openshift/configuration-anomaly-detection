// Package checks holds commands for periodic checks not triggered by a PagerDuty alert
package checks

import (
	"errors"
	"fmt"
	v1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/aws"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"
	"github.com/openshift/configuration-anomaly-detection/pkg/services/ccam"
	"github.com/spf13/cobra"
)

const (
	OcmClustersRequestPageSize = 100
)

// Cmd represents the entry point for credentials checks
var Cmd = &cobra.Command{
	Use:   "credentials",
	Short: "Determines if any managed clusters have missing credentials.",
	Long: `Determines if any managed clusters have missing credentials. If the command determines that
they a cluster's credentials are missing, the cluster is placed into limited support. If the cluster is
already in limited support, the command will evaluate if the credentials have been restored and remove
it from limited support if appropriate.`,
	RunE: run,
}

func run(_ *cobra.Command, _ []string) error {
	awsClient, err := aws.GetClient()
	if err != nil {
		return fmt.Errorf("could not initialize aws client: %w", err)
	}

	ocmClient, err := ocm.GetClient()
	if err != nil {
		return fmt.Errorf("could not initialize ocm client: %w", err)
	}

	pdClient, err := pagerduty.GetClientNoWebhook()
	if err != nil {
		return fmt.Errorf("could not initialize pagerduty client: %w", err)
	}

	var errs []error
	morePages := true
	for page := 1; morePages; page++ {
		result, err := ocmClient.ListManagedClusters(OcmClustersRequestPageSize, page)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to list managed clusters: %w", err))
			continue
		}

		// We've hit the end of the result set - stop paging
		if result.Items().Len() < OcmClustersRequestPageSize {
			morePages = false
		}

		result.Items().Each(func(cluster *v1.Cluster) bool {
			_, err = ccam.InvestigateCCAM(awsClient, ocmClient, pdClient, cluster)
			if err != nil {
				errs = append(errs, err)
			}

			return true
		})
	}
	return errors.Join(errs...)
}
