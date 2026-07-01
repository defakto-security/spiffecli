package cmd

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

type DocumentedCmd struct {
	document        bool
	SidebarPosition int
	SubCommands     map[string]DocumentedCmd
}

var docsPath string

func GenerateCommandDocs(cmd *cobra.Command, commandsToDocument map[string]DocumentedCmd, usageTree string) error {
	commands := cmd.Commands()

	for _, subCmd := range commands {
		cmdInfo, ok := commandsToDocument[subCmd.Use]

		if ok {
			newUsageTree := strings.Trim(fmt.Sprintf("%s %s", usageTree, subCmd.Use), " ")
			filename := strings.Trim(fmt.Sprintf("%s-%s.md", usageTree, subCmd.Use), " -")

			if cmdInfo.document {
				f, err := os.Create(filepath.Join(docsPath, filename)) //nolint:gosec // user-provided docs output path
				if err != nil {
					return fmt.Errorf("failed to create docs file: %w", err)
				}
				defer func() { _ = f.Close() }()

				_, err = fmt.Fprintf(f, `---
title: %s
sidebar_position: %d
---
`, newUsageTree, cmdInfo.SidebarPosition)
				if err != nil {
					return fmt.Errorf("failed to write docs for command %s: %w", newUsageTree, err)
				}

				var buf bytes.Buffer
				if err = doc.GenMarkdown(subCmd, &buf); err != nil {
					return fmt.Errorf("failed to generate markdown for command: %w", err)
				}

				// Cobra appends a "SEE ALSO" section that links to
				// parent-command pages this generator does not emit, plus a
				// timestamped footer. Strip both so the docs site has no
				// broken links and regeneration stays deterministic.
				body := buf.String()
				if idx := strings.Index(body, "### SEE ALSO"); idx != -1 {
					body = strings.TrimRight(body[:idx], "\n") + "\n"
				}

				if _, err = f.WriteString(body); err != nil {
					return fmt.Errorf("failed to write docs for command %s: %w", newUsageTree, err)
				}
			}

			err := GenerateCommandDocs(subCmd, cmdInfo.SubCommands, newUsageTree)
			if err != nil {
				return fmt.Errorf("failed to generate subcommand docs: %w", err)
			}
		}
	}

	return nil
}

func init() {
	commandsToDocument := map[string]DocumentedCmd{
		"run": {document: true, SidebarPosition: 2},
		"get": {SubCommands: map[string]DocumentedCmd{
			"x509-svid": {document: true, SidebarPosition: 3},
			"jwt-svid":  {document: true, SidebarPosition: 4},
			"bundle":    {document: true, SidebarPosition: 5},
		}},
		"verify": {SubCommands: map[string]DocumentedCmd{
			"x509-svid": {document: true, SidebarPosition: 6},
			"jwt-svid":  {document: true, SidebarPosition: 7},
			"x509":      {document: true, SidebarPosition: 8},
		}},
		"inspect": {SubCommands: map[string]DocumentedCmd{
			"jwt":  {document: true, SidebarPosition: 9},
			"jwks": {document: true, SidebarPosition: 10},
			"x509": {document: true, SidebarPosition: 11},
		}},
		"docs": {document: true, SidebarPosition: 12},
	}

	docsCmd := &cobra.Command{
		Use:   "docs",
		Short: "Generate documentation for spiffecli",
		RunE: func(cmd *cobra.Command, args []string) error {
			return GenerateCommandDocs(rootCmd, commandsToDocument, "")
		},
		Hidden: true,
	}

	docsCmd.Flags().StringVarP(&docsPath, "output", "o", "./documentation/docs/", "Where to output the documentation. Default is ./documenatation/docs")

	rootCmd.AddCommand(docsCmd)
}
