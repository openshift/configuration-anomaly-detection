package ai

import (
	"context"
	"fmt"
	"os"

	"github.com/openai/openai-go"
	"github.com/openai/openai-go/option"
)

var (
	url = "https://mistral-small-maas-maas.apps.rosa.hcmaii01ue1.a9ro.p3.openshiftapps.com/v1"
)

type AIClient struct {
	Client *openai.Client
	model  openai.ChatModel
}

func New() *AIClient {
	client := openai.NewClient(
		option.WithHeaderAdd("Authorization", fmt.Sprintf("Bearer %s", os.Getenv("CAD_HCM_AI_TOKEN"))),
		option.WithBaseURL(url),
	)
	model := openai.ChatModel("mistral-small-maas")
	return &AIClient{
		Client: &client,
		model:  model,
	}
}

func (ai *AIClient) Ask(ask string) (string, error) {
	messages := []openai.ChatCompletionMessageParamUnion{
		openai.SystemMessage("You are a Site Reliability Engineer for Managed Openshift"),
		openai.UserMessage(ask),
	}
	aiOutput, err := ai.Client.Chat.Completions.New(context.TODO(), openai.ChatCompletionNewParams{
		Model:    ai.model,
		Messages: messages,
	})
	if err != nil {
		return "", err
	}
	return aiOutput.Choices[0].Message.Content, nil
}
