package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateCommandDocs(t *testing.T) {
	tmpDir := t.TempDir() + "/"
	docsPath = tmpDir

	// Test with empty map - should iterate subcommands and return nil
	err := GenerateCommandDocs(rootCmd, map[string]DocumentedCmd{}, "")
	require.NoError(t, err)
}

func TestGenerateCommandDocs_WithSubcommand(t *testing.T) {
	tmpDir := t.TempDir() + "/"
	docsPath = tmpDir

	// Document the inspect command
	commandsToDocument := map[string]DocumentedCmd{
		"inspect": {
			SubCommands: map[string]DocumentedCmd{
				"jwt": {document: true, SidebarPosition: 1},
			},
		},
	}

	err := GenerateCommandDocs(rootCmd, commandsToDocument, "")
	require.NoError(t, err)
}
