//go:build windows

package cmd

import "os"

// shutdownSignals are the OS signals that trigger a graceful watch shutdown.
// SIGTERM is not available on Windows; os.Interrupt (Ctrl+C) is used instead.
var shutdownSignals = []os.Signal{os.Interrupt}
