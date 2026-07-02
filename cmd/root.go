package cmd

import (
	"fmt"
	"os"
	"runtime/debug"

	"github.com/spf13/cobra"
)

// Build metadata. Overridden at release time by main via SetVersionInfo,
// which receives values injected by GoReleaser with -ldflags -X.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "spiffecli",
	Short: "A SPIFFE CLI",
	Long:  `The SPIFFE utility CLI`,
	CompletionOptions: cobra.CompletionOptions{
		DisableDefaultCmd: true,
	},
	SilenceUsage: true,
}

// SetVersionInfo wires build-time version details into the root command,
// enabling the --version flag. Empty arguments are ignored so callers can
// pass through unset ldflags without clobbering the defaults.
func SetVersionInfo(v, c, d string) {
	if v != "" {
		version = v
	}
	if c != "" {
		commit = c
	}
	if d != "" {
		date = d
	}
	// When built without ldflags (e.g. `go install`), recover the module
	// version from the embedded build info instead of showing "dev".
	if version == "dev" {
		if info, ok := debug.ReadBuildInfo(); ok &&
			info.Main.Version != "" && info.Main.Version != "(devel)" {
			version = info.Main.Version
		}
	}
	rootCmd.Version = version
	rootCmd.SetVersionTemplate(
		fmt.Sprintf("spiffecli %s\ncommit: %s\nbuilt:  %s\n", version, commit, date),
	)
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
