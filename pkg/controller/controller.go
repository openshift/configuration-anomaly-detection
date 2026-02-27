package controller

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/openshift/configuration-anomaly-detection/pkg/backplane"
	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/ccam"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/chgm"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/precheck"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/managedcloud"
	"github.com/openshift/configuration-anomaly-detection/pkg/metrics"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"
	"github.com/openshift/configuration-anomaly-detection/pkg/types"
	"go.uber.org/zap"
)

const pagerdutyTitlePrefix = "[CAD Investigated]"

type PagerDutyConfig struct {
	PayloadPath string
}

func (p *PagerDutyConfig) Validate() error {
	if p.PayloadPath == "" {
		return fmt.Errorf("PayloadPath can not be empty")
	}
	return nil
}

type ManualConfig struct {
	ClusterId         string
	InvestigationName string
	DryRun            bool
}

func (p *ManualConfig) Validate() error {
	if p.ClusterId == "" || p.InvestigationName == "" {
		return fmt.Errorf("ClusterId and InvestigationName can not be empty")
	}
	return nil
}

type CommonConfig struct {
	LogLevel   string
	Identifier string
}

type Controller interface {
	Investigate(ctx context.Context) error
}

type investigationRunner struct {
	ocmClient    *ocm.SdkClient
	bpClient     backplane.Client
	executor     executor.Executor
	logger       *zap.SugaredLogger
	dependencies *Dependencies
	dryRun       bool
}

type ControllerOptions struct {
	Common CommonConfig
	Pd     *PagerDutyConfig // nil if not via PD
	Manual *ManualConfig    // nil if not manual
}

type Dependencies struct {
	OCMClient           *ocm.SdkClient
	BackplaneClient     backplane.Client
	BackplaneURL        string
	BackplaneProxy      string
	AWSProxy            string
	ExperimentalEnabled bool
}

// Retry configuration for transient infrastructure errors
const (
	maxInvestigationRetries = 3
	initialRetryBackoff     = 1 * time.Second
	maxRetryBackoff         = 10 * time.Second
)

func (d *Dependencies) Cleanup() {
	// Currently no cleanup needed at dependency level
	// Individual investigations handle their own cleanup (RestConfig, OCClient)
	// But this provides a hook for future needs
}

// initializeDependencies loads environment variables and creates shared clients
func initializeDependencies() (*Dependencies, error) {
	// Load k8s environment variables
	backplaneURL := os.Getenv("BACKPLANE_URL")
	if backplaneURL == "" {
		return nil, fmt.Errorf("missing required environment variable BACKPLANE_URL")
	}

	// Load managedcloud environment variables
	backplaneInitialARN := os.Getenv("BACKPLANE_INITIAL_ARN")
	if backplaneInitialARN == "" {
		return nil, fmt.Errorf("missing required environment variable BACKPLANE_INITIAL_ARN")
	}

	backplaneProxy := os.Getenv("BACKPLANE_PROXY")
	awsProxy := os.Getenv("AWS_PROXY")

	// Set managedcloud environment configuration for this session
	managedcloud.SetBackplaneURL(backplaneURL)
	managedcloud.SetBackplaneInitialARN(backplaneInitialARN)
	managedcloud.SetBackplaneProxy(backplaneProxy)
	managedcloud.SetAWSProxy(awsProxy)

	// Load OCM environment variables
	ocmClientID := os.Getenv("CAD_OCM_CLIENT_ID")
	if ocmClientID == "" {
		return nil, fmt.Errorf("missing required environment variable CAD_OCM_CLIENT_ID")
	}

	ocmClientSecret := os.Getenv("CAD_OCM_CLIENT_SECRET")
	if ocmClientSecret == "" {
		return nil, fmt.Errorf("missing required environment variable CAD_OCM_CLIENT_SECRET")
	}

	ocmURL := os.Getenv("CAD_OCM_URL")
	if ocmURL == "" {
		return nil, fmt.Errorf("missing required environment variable CAD_OCM_URL")
	}

	experimentalEnabledVar := os.Getenv("CAD_EXPERIMENTAL_ENABLED")
	experimentalEnabled, _ := strconv.ParseBool(experimentalEnabledVar)

	// Create OCM client
	ocmClient, err := ocm.New(ocmClientID, ocmClientSecret, ocmURL)
	if err != nil {
		return nil, fmt.Errorf("could not initialize ocm client: %w", err)
	}

	// Create backplane client
	config := backplane.Config{
		OcmClient: ocmClient,
		BaseURL:   backplaneURL,
		ProxyURL:  backplaneProxy,
	}
	bpClient, err := backplane.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("could not construct backplane-client")
	}

	return &Dependencies{
		OCMClient:           ocmClient,
		BackplaneClient:     bpClient,
		BackplaneURL:        backplaneURL,
		BackplaneProxy:      backplaneProxy,
		AWSProxy:            awsProxy,
		ExperimentalEnabled: experimentalEnabled,
	}, nil
}

// This is the main function to interact with the controller.
// It will determine which type of controller to build based on the passed options and run the required investigation.
func Run(opts ControllerOptions) error {
	deps, err := initializeDependencies()
	if err != nil {
		return err
	}
	defer deps.Cleanup()

	ctrl, err := NewController(opts, deps)
	if err != nil {
		return err
	}

	return ctrl.Investigate(context.Background())
}

// Factory function - determines which controller to create based on options
func NewController(opts ControllerOptions, deps *Dependencies) (Controller, error) {
	// Validate that exactly one controller type is specified
	if (opts.Pd != nil && opts.Manual != nil) ||
		(opts.Pd == nil && opts.Manual == nil) {
		return nil, fmt.Errorf("must specify exactly one controller type")
	}

	if opts.Pd != nil {
		if err := opts.Pd.Validate(); err != nil {
			return nil, fmt.Errorf("invalid webhook config: %w", err)
		}

		// Load and parse PagerDuty payload
		payload, err := os.ReadFile(opts.Pd.PayloadPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read webhook payload: %w", err)
		}

		pdClient, err := pagerduty.GetPDClient(payload)
		if err != nil {
			return nil, fmt.Errorf("could not initialize pagerduty client: %w", err)
		}

		// Initialize logger early (we'll update with cluster ID later)
		logger := logging.InitLogger(opts.Common.LogLevel, opts.Common.Identifier, "")

		return &PagerDutyController{
			config:   opts.Common,
			pd:       *opts.Pd,
			pdClient: pdClient,
			investigationRunner: investigationRunner{
				ocmClient:    deps.OCMClient,
				bpClient:     deps.BackplaneClient,
				executor:     executor.NewWebhookExecutor(deps.OCMClient, pdClient, deps.BackplaneClient, logger),
				logger:       logger,
				dependencies: deps,
			},
		}, nil
	}

	if opts.Manual != nil {
		if err := opts.Manual.Validate(); err != nil {
			return nil, fmt.Errorf("invalid manual config: %w", err)
		}

		// Initialize logger for manual runs
		logger := logging.InitLogger(opts.Common.LogLevel, opts.Common.Identifier, opts.Manual.ClusterId)

		return &ManualController{
			config: opts.Common,
			manual: *opts.Manual,
			investigationRunner: investigationRunner{
				ocmClient:    deps.OCMClient,
				bpClient:     deps.BackplaneClient,
				executor:     executor.NewManualExecutor(deps.OCMClient, deps.BackplaneClient, logger),
				logger:       logger,
				dependencies: deps,
				dryRun:       opts.Manual.DryRun,
			},
		}, nil
	}

	return nil, fmt.Errorf("no valid controller configuration provided")
}

func (c *investigationRunner) runInvestigation(ctx context.Context, clusterId string, inv investigation.Investigation, pdClient *pagerduty.SdkClient) error {
	metrics.Inc(metrics.Alerts, inv.Name())

	builder, err := investigation.NewResourceBuilder(c.ocmClient, c.bpClient, clusterId, inv.Name(), c.dependencies.BackplaneURL)
	if pdClient != nil {
		builder.WithPdClient(pdClient)
	}
	if err != nil {
		return fmt.Errorf("failed to create resource builder: %w", err)
	}

	defer func() {
		// The builder caches resources, so we can access them here even if a later step failed.
		// We ignore the error here because we just want to get any resources that were created.
		resources, _ := builder.Build()

		// Cleanup rest config if it exists
		if resources != nil && resources.RestConfig != nil {
			// Failing the rest config cleanup call is not critical
			// There is garbage collection for the RBAC within MCC https://issues.redhat.com/browse/OSD-27692
			// We only log the error for now but could add it to the investigation notes or handle differently
			logging.Info("Cleaning cluster api access")
			deferErr := resources.RestConfig.Clean()
			if deferErr != nil {
				logging.Error(deferErr)
			}
		}

		if resources != nil && resources.OCClient != nil {
			logging.Info("Cleaning oc kubeconfig file access")
			deferErr := resources.OCClient.Clean()
			if deferErr != nil {
				logging.Error(deferErr)
			}
		}
		if err != nil {
			handleCADFailure(err, builder, pdClient)
		}
	}()

	preCheck := precheck.ClusterStatePrecheck{}
	result, err := preCheck.Run(builder)
	if err != nil {
		return err
	}
	if len(result.Actions) > 0 {
		if err = c.executeActions(builder, &result, "precheck"); err != nil {
			return fmt.Errorf("failed to execute precheck actions: %w", err)
		}
		// We stop if the precheck returns any action this mean we do not want to run anything else.
		return nil
	}
	if result.StopInvestigations != nil {
		logging.Errorf("Stopping investigations due to: %w", result.StopInvestigations)
		return nil
	}

	ccamInvestigation := ccam.CloudCredentialsCheck{}
	result, err = ccamInvestigation.Run(builder)
	if err != nil {
		return err
	}
	// FIXME: Once all migrations are converted this can be removed.
	updateMetrics(inv.Name(), &result)

	// Execute ccam actions if any
	if len(result.Actions) > 0 {
		if err := c.executeActions(builder, &result, "ccam"); err != nil {
			return fmt.Errorf("failed to execute ccam actions: %w", err)
		}
		chgmInv := chgm.Investigation{}
		// In case of a CHGM there is no need to investigate further now, other investigations that don't need AWS might
		// be able to proceed. To handle this case we will *only* return when CCAM found something and it's CGHM - handling
		// non-AWS access is up to following investigations.
		if inv.AlertTitle() == chgmInv.AlertTitle() {
			return nil
		}
	}

	logging.Infof("Starting investigation for %s", inv.Name())
	result, attempts, err := runInvestigationWithRetry(inv, builder)
	if err != nil {
		return fmt.Errorf("investigation failed after %d attempt(s): %w", attempts, err)
	}
	updateMetrics(inv.Name(), &result)

	// Execute investigation actions if any
	if err := c.executeActions(builder, &result, inv.Name()); err != nil {
		return fmt.Errorf("failed to execute %s actions: %w", inv.Name(), err)
	}

	a := executor.PagerDutyTitleUpdate{Prefix: pagerdutyTitlePrefix}
	result = investigation.InvestigationResult{
		Actions: []types.Action{&a},
	}
	return c.executeActions(builder, &result, inv.Name())
}

// runInvestigationWithRetry executes an investigation with retry logic for transient errors.
// It retries up to maxInvestigationRetries times with exponential backoff for InfrastructureErrors.
// Returns the result, the number of attempts made, and the final error.
func runInvestigationWithRetry(
	inv investigation.Investigation,
	builder investigation.ResourceBuilder,
) (investigation.InvestigationResult, int, error) {
	var result investigation.InvestigationResult
	var err error

	maxAttempts := maxInvestigationRetries + 1

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		result, err = inv.Run(builder)

		if err == nil { // Success
			if attempt > 1 {
				logging.Infof("Investigation succeeded on attempt %d", attempt)
			}
			return result, attempt, nil
		}

		if !investigation.IsInfrastructureError(err) {
			logging.Debugf("Non-retriable error encountered: %v", err)
			return result, attempt, err
		}

		// Infra error; retry if any attempts left
		if attempt < maxAttempts {
			backoff := calculateBackoff(attempt)
			logging.Warnf("Infrastructure error on attempt %d/%d, retrying in %v: %v",
				attempt, maxAttempts, backoff, err)
			time.Sleep(backoff)
		} else {
			logging.Errorf("Infrastructure error on final attempt %d/%d: %v",
				attempt, maxAttempts, err)
		}
	}

	return result, maxAttempts, err
}

// calculateBackoff returns an exponential backoff duration for the given attempt.
// Backoff doubles each attempt (1s, 2s, 4s, ...) up to maxRetryBackoff.
func calculateBackoff(attempt int) time.Duration {
	backoff := initialRetryBackoff << (attempt - 1) // 1s, 2s, 4s, ...
	if backoff > maxRetryBackoff {
		backoff = maxRetryBackoff
	}
	return backoff
}

func handleCADFailure(err error, rb investigation.ResourceBuilder, pdClient *pagerduty.SdkClient) {
	logging.Errorf("CAD investigation failed: %v", err)
	resources, err := rb.Build()
	if err != nil {
		logging.Errorf("resource builder failed with error: %v", err)
	}

	var docErr *ocm.DocumentationMismatchError
	if errors.As(err, &docErr) {
		escalateDocumentationMismatch(docErr, resources, pdClient)
		return
	}

	var notes string
	if resources != nil && resources.Notes != nil {
		resources.Notes.AppendWarning("🚨 CAD investigation failed, CAD team has been notified. Please investigate manually. 🚨")
		notes = resources.Notes.String()
	} else {
		notes = "🚨 CAD investigation failed prior to resource initialization, CAD team has been notified. Please investigate manually. 🚨"
	}

	if pdClient != nil {
		pdErr := pdClient.EscalateIncidentWithNote(notes)
		if pdErr != nil {
			logging.Errorf("Failed to escalate notes to PagerDuty: %v", pdErr)
		} else {
			logging.Info("CAD failure & incident notes added to PagerDuty")
		}
	} else {
		logging.Errorf("Failed to obtain PagerDuty client, unable to escalate CAD failure to PagerDuty notes.")
	}
}

func updateMetrics(investigationName string, result *investigation.InvestigationResult) {
	if result.ServiceLogSent.Performed {
		metrics.Inc(metrics.ServicelogSent, append([]string{investigationName}, result.ServiceLogSent.Labels...)...)
	}
	if result.ServiceLogPrepared.Performed {
		metrics.Inc(metrics.ServicelogPrepared, append([]string{investigationName}, result.ServiceLogPrepared.Labels...)...)
	}
	if result.LimitedSupportSet.Performed {
		metrics.Inc(metrics.LimitedSupportSet, append([]string{investigationName}, result.LimitedSupportSet.Labels...)...)
	}
	if result.MustGatherPerformed.Performed {
		metrics.Inc(metrics.MustGatherPerformed, append([]string{investigationName}, result.MustGatherPerformed.Labels...)...)
	}
	if result.EtcdDatabaseAnalysis.Performed {
		metrics.Inc(metrics.EtcdDatabaseAnalysis, append([]string{investigationName}, result.EtcdDatabaseAnalysis.Labels...)...)
	}
}

// executeActions executes actions from an investigation result using the controller's executor
func (c *investigationRunner) executeActions(
	builder investigation.ResourceBuilder,
	result *investigation.InvestigationResult,
	investigationName string,
) error {
	// If no actions, return early
	if len(result.Actions) == 0 {
		logging.Debug("No actions to execute")
		return nil
	}

	// Build resources to get cluster and notes
	resources, err := builder.Build()
	if err != nil {
		return fmt.Errorf("failed to build resources for action execution: %w", err)
	}

	// Execute actions with default options using controller's executor
	input := &executor.ExecutorInput{
		InvestigationName: investigationName,
		Actions:           result.Actions,
		Cluster:           resources.Cluster,
		Notes:             resources.Notes,
		Options: executor.ExecutionOptions{
			DryRun:            c.dryRun,
			StopOnError:       false, // Continue executing actions even if one fails
			MaxRetries:        3,
			ConcurrentActions: true, // Use concurrent execution for better performance
		},
	}

	logging.Infof("Executing %d actions for %s", len(result.Actions), investigationName)
	if err := c.executor.Execute(context.Background(), input); err != nil {
		// Log the error but don't fail the investigation
		// This matches the current behavior where we log failures but continue
		logging.Errorf("Action execution failed for %s: %v", investigationName, err)
		return err
	}

	logging.Infof("Successfully executed all actions for %s", investigationName)
	return nil
}
