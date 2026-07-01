package cmd

import (
	_ "embed"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/manifoldco/promptui"
	"github.com/spf13/cobra"
	"github.com/defakto-security/spiffecli/internal/wlapi"
)

//go:embed dev.toml
var defaultConfig string

type Options struct {
	ConfigFile string
}

func init() {
	var opts Options

	// runCmd represents the run command
	var runCmd = &cobra.Command{
		Use:   "run",
		Short: "Runs a dev server that exposes a simulated Workload API",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if opts.ConfigFile == "" {
				return errors.New("required flag \"config\" not set")
			}

			// Expand ~ to the user's home directory if necessary
			if strings.HasPrefix(opts.ConfigFile, "~/") {
				home, err := os.UserHomeDir()
				if err != nil {
					return err
				}
				opts.ConfigFile = filepath.Join(home, opts.ConfigFile[len("~/"):])
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			prompter := NewPromptUIPrompter()

			// If the config file doesn't exist, write the default config there
			if _, err := os.Stat(opts.ConfigFile); os.IsNotExist(err) {
				cmd.Printf("Unable to find an existing configuration (see --config flag).\n\n")
				cmd.Printf("If you continue, a default configuration will be used and saved at %s\n", opts.ConfigFile)
				prompt := promptui.Prompt{
					Label:     "Continue",
					IsConfirm: true,
				}
				if _, err := prompter.Run(prompt); err != nil {
					return nil
				}

				// Create directory if it doesn't exist
				configDir := filepath.Dir(opts.ConfigFile)
				if _, err := os.Stat(configDir); os.IsNotExist(err) {
					if err := os.MkdirAll(configDir, 0750); err != nil {
						return err
					}
				}

				if err := os.WriteFile(opts.ConfigFile, []byte(defaultConfig), 0644); err != nil { //nolint:gosec // config file, 0644 is fine
					return err
				}
				cmd.Printf("\nSaved %s\n\n", opts.ConfigFile)
			}
			cfg, err := wlapi.LoadConfig(opts.ConfigFile)
			if err != nil {
				return err
			}
			return wlapi.Run(cmd.Context(), cfg)
		},
	}

	rootCmd.AddCommand(runCmd)

	runCmd.Flags().StringVar(&opts.ConfigFile, "config", "~/.spirl/dev.toml", "The dev configuration file, will be created if it doesn't exist")
}
