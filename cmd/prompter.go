package cmd

import "github.com/manifoldco/promptui"

type Prompter interface {
	Run(promptui.Prompt) (string, error)
}

type PromptUIPrompter struct{}

func NewPromptUIPrompter() *PromptUIPrompter {
	return &PromptUIPrompter{}
}

func (p *PromptUIPrompter) Run(prompt promptui.Prompt) (string, error) {
	return prompt.Run()
}
