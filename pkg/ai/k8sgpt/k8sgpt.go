package k8sgpt

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	k8sgpt_ai "github.com/k8sgpt-ai/k8sgpt/pkg/ai"
	"github.com/k8sgpt-ai/k8sgpt/pkg/analysis"
	"github.com/k8sgpt-ai/k8sgpt/pkg/cache"
	gptK8sClient "github.com/k8sgpt-ai/k8sgpt/pkg/kubernetes"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	model = "mistral-small-maas"
)

func K8sGptAnalysis(k8sRestConfig *rest.Config) (string, error) {
	ctrlClient, err := client.New(k8sRestConfig, client.Options{Scheme: runtime.NewScheme()})
	if err != nil {
		return "", errors.New("unable to init ctrlClient")
	}
	clientset := kubernetes.NewForConfigOrDie(k8sRestConfig)

	client := &gptK8sClient.Client{CtrlClient: ctrlClient, Config: k8sRestConfig, Client: clientset}

	aiToken := os.Getenv("CAD_HCM_AI_TOKEN")
	if aiToken == "" {
		return "", errors.New("could not find CAD_HCM_AI_TOKEN env")
	}

	aiClient := k8sgpt_ai.NewClient("openai")
	aiProvider := &k8sgpt_ai.AIProvider{
		Name:     "openai",
		Model:    model,
		BaseURL:  "https://mistral-small-maas-maas.apps.rosa.hcmaii01ue1.a9ro.p3.openshiftapps.com/v1", // TODO: Let's not hardcode this.
		Password: aiToken,
	}
	aiClient.Configure(aiProvider)

	cache, err := cache.GetCacheConfiguration()
	cache.DisableCache()

	a := &analysis.Analysis{
		Context:        context.Background(),
		Filters:        []string{"Pod", "Deployment", "ReplicaSet", "PersistentVolumeClaim", "Service", "Ingress", "StatefulSet", "CronJob", "Node", "ValidatingWebhookConfiguration", "MutatingWebhookConfiguration"},
		Client:         client,
		Language:       "english",
		Namespace:      "",
		LabelSelector:  "",
		Cache:          cache,
		Explain:        true,
		MaxConcurrency: 10,
		WithDoc:        false,
		WithStats:      false,
		AIClient:       aiClient,
	}

	a.RunAnalysis()

	var output string
	anonymize := false
	if err := a.GetAIResults(output, anonymize); err != nil {
		return "", fmt.Errorf("unable to get ai results: %w", err)
	}

	return formatOutput(a)
}

func formatOutput(a *analysis.Analysis) (string, error) {
	var output strings.Builder

	output.WriteString("🤖🔧 AI Analysis Results 🔧🤖\n")
	output.WriteString(fmt.Sprintf("Model: %s\n", model))
	if len(a.Errors) != 0 {
		output.WriteString("⚠️ Analysis failures: \n")
		for _, aerror := range a.Errors {
			output.WriteString(fmt.Sprintf("- %s\n", aerror))
		}
	}
	if len(a.Results) == 0 {
		output.WriteString("✅ No cluster problems detected\n")
		return output.String(), nil
	}
	output.WriteString(fmt.Sprintf("🔍 %d cluster issues detected\n", len(a.Results)))
	output.WriteString("================\n\n")

	for _, result := range a.Results {
		if result.Kind != "" {
			output.WriteString(fmt.Sprintf("Kind: %s\n", result.Kind))
		}

		if result.Name != "" {
			output.WriteString(fmt.Sprintf("Name: %s\n", result.Name))
		}

		if result.ParentObject != "" {
			output.WriteString(fmt.Sprintf("ParentObject: %s\n", result.ParentObject))
		}

		if len(result.Error) > 0 {
			output.WriteString("Issues:\n")
			for _, err := range result.Error {
				output.WriteString(fmt.Sprintf("- %s\n", err.Text))
				if err.KubernetesDoc != "" {
					output.WriteString(fmt.Sprintf("  Kubernetes Doc: %s\n", err.KubernetesDoc))
				}
			}
		}

		if result.Details != "" {
			output.WriteString(fmt.Sprintf("Details: %s\n", result.Details))
		}

		output.WriteString("\n------------------------------------------------------------\n\n")
	}

	return output.String(), nil
}
