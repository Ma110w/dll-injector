package main

import (
	"github.com/whispin/dll-injector/internal/ui"
	"go.uber.org/zap"
)

func main() {
	// Create UI app first so we can use its logger - 使用更紧凑的窗口尺寸
	app := ui.NewApplication("DLL Injector", 1000, 500)

	// Log startup using app's logger (will show in UI)
	logger := app.Log()
	logger.Info("DLL Injector starting")

	// Start the application
	if err := app.Run(); err != nil {
		logger.Error("Application runtime error", zap.Error(err))
	}

	// Closing message is already logged in app.Close()
}
