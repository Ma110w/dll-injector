package main

import (
	"github.com/whispin/dll-injector/internal/ui"
	"go.uber.org/zap"
)

func main() {
	// Create UI app first so we can use its logger
	app := ui.NewApplication("DLL Injector", 1035, 700)

	// Log startup using app's logger (will show in UI)
	logger := app.Log()
	logger.Info("DLL Injector starting")

	// Start the application
	if err := app.Run(); err != nil {
		logger.Error("Application runtime error", zap.Error(err))
	}

	// Closing message is already logged in app.Close()
}
