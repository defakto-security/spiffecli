//go:build !windows

package cmd

import (
	"os"
	"syscall"
)

// shutdownSignals are the OS signals that trigger a graceful watch shutdown.
var shutdownSignals = []os.Signal{os.Interrupt, syscall.SIGTERM}
