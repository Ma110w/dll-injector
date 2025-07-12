package ui

import (
	"fmt"
	"image/color"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/AllenDang/giu"
	"github.com/whispin/dll-injector/internal/injector"
	"github.com/whispin/dll-injector/internal/process"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Application represents the main GUI application using giu
type Application struct {
	title       string
	width       int32
	height      int32
	processInfo *process.Info
	processes   []process.ProcessEntry
	logger      *zap.Logger

	// UI state
	selectedDllPath     string
	selectedPID         int32
	selectedProcessName string
	searchText          string
	logText             string
	logLines            []string
	maxLogLines         int

	// Injection options
	injectionMethod int32
	methodNames     []string

	// Anti-detection options
	memoryLoad             bool
	peHeaderErasure        bool
	entryPointErase        bool
	manualMapping          bool
	invisibleMemory        bool
	pathSpoofing           bool
	legitProcessInjection  bool
	pteSpoofing            bool
	vadManipulation        bool
	removeVADNode          bool
	allocBehindThreadStack bool
	directSyscalls         bool

	// Enhanced options
	randomizeAllocation  bool
	delayedExecution     bool
	multiStageInjection  bool
	antiDebugTechniques  bool
	processHollowing     bool
	atomBombing          bool
	doppelgangingProcess bool
	ghostWriting         bool
	moduleStomping       bool
	threadHijacking      bool
	apcQueueing          bool
	memoryFluctuation    bool
	antiVMTechniques     bool
	processMirroring     bool
	stealthyThreads      bool

	// UI state
	showAboutDialog    bool
	showHelpDialog     bool
	showConfirmDialog  bool
	showProgressDialog bool
	showSuccessDialog  bool
	confirmDialogText  string
	progressText       string
	successText        string

	// Mutex for thread safety
	mu sync.RWMutex
}

// LoggerAdapter adapts zap.Logger to injector.Logger interface
type LoggerAdapter struct {
	logger *zap.Logger
}

// Info implements injector.Logger interface
func (l *LoggerAdapter) Info(msg string, fields ...interface{}) {
	zapFields := convertToZapFields(fields...)
	l.logger.Info(msg, zapFields...)
}

// Error implements injector.Logger interface
func (l *LoggerAdapter) Error(msg string, fields ...interface{}) {
	zapFields := convertToZapFields(fields...)
	l.logger.Error(msg, zapFields...)
}

// Warn implements injector.Logger interface
func (l *LoggerAdapter) Warn(msg string, fields ...interface{}) {
	zapFields := convertToZapFields(fields...)
	l.logger.Warn(msg, zapFields...)
}

// Debug implements injector.Logger interface
func (l *LoggerAdapter) Debug(msg string, fields ...interface{}) {
	zapFields := convertToZapFields(fields...)
	l.logger.Debug(msg, zapFields...)
}

// convertToZapFields converts interface{} pairs to zap.Field objects
func convertToZapFields(fields ...interface{}) []zap.Field {
	zapFields := make([]zap.Field, 0, len(fields)/2)
	for i := 0; i < len(fields)-1; i += 2 {
		if key, ok := fields[i].(string); ok {
			zapFields = append(zapFields, zap.Any(key, fields[i+1]))
		}
	}
	return zapFields
}

// NewApplication creates a new GUI application instance
func NewApplication(title string, width, height int) *Application {
	app := &Application{
		title:       title,
		width:       int32(width),
		height:      int32(height),
		processInfo: process.NewInfo(),
		selectedPID: -1,
		maxLogLines: 1000,
		methodNames: []string{
			"Standard Injection",
			"SetWindowsHookEx",
			"QueueUserAPC",
			"Early Bird APC",
			"DLL Notification",
			"Job Object",
		},
	}

	// Initialize logger
	app.setupLogger()

	// Initialize process info
	app.refreshProcessList()

	return app
}

// setupLogger initializes the logger
func (app *Application) setupLogger() {
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.CapitalLevelEncoder,
		EncodeTime:     zapcore.TimeEncoderOfLayout("15:04:05"),
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	// Create a custom core that writes to our log display
	core := zapcore.NewCore(
		zapcore.NewConsoleEncoder(encoderConfig),
		zapcore.AddSync(&logWriter{app: app}),
		zapcore.InfoLevel,
	)

	app.logger = zap.New(core)

	// Set the global logger for injector package
	loggerAdapter := &LoggerAdapter{logger: app.logger}
	injector.SetLogger(loggerAdapter)
}

// logWriter implements io.Writer to capture log output
type logWriter struct {
	app *Application
}

func (lw *logWriter) Write(p []byte) (n int, err error) {
	text := strings.TrimSpace(string(p))
	if text != "" {
		lw.app.addLogLine(text)
	}
	return len(p), nil
}

// addLogLine adds a line to the log display
func (app *Application) addLogLine(line string) {
	app.mu.Lock()
	defer app.mu.Unlock()

	app.logLines = append(app.logLines, line)
	if len(app.logLines) > app.maxLogLines {
		app.logLines = app.logLines[1:]
	}

	app.logText = strings.Join(app.logLines, "\n")
}

// refreshProcessList refreshes the process list
func (app *Application) refreshProcessList() {
	if err := app.processInfo.Refresh(); err != nil {
		app.logger.Error("Failed to refresh process list", zap.Error(err))
		return
	}

	app.mu.Lock()
	app.processes = app.processInfo.GetProcesses()
	app.mu.Unlock()

	app.logger.Info("Process list refreshed", zap.Int("count", len(app.processes)))
}

// Run starts the GUI application
func (app *Application) Run() error {
	app.logger.Info("Starting GUI application", zap.String("title", app.title), zap.Int32("width", app.width), zap.Int32("height", app.height))

	// Create master window with explicit flags
	wnd := giu.NewMasterWindow(app.title, int(app.width), int(app.height), giu.MasterWindowFlagsNotResizable)

	app.logger.Info("Master window created, starting main loop...")

	// Run the main loop
	wnd.Run(app.loop)

	app.logger.Info("GUI application finished")
	return nil
}

// Log returns the application logger
func (app *Application) Log() *zap.Logger {
	return app.logger
}

// loop is the main UI loop
func (app *Application) loop() {
	// Simple working layout based on our test
	giu.SingleWindow().Layout(
		giu.Column(
			giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 255, G: 255, B: 255, A: 255}).To(
				giu.Label("DLL Injector"),
			),
			giu.Separator(),
			giu.Spacing(),

			// DLL File Selection
			giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 51, G: 204, B: 255, A: 255}).To(
				giu.Label("DLL File Selection:"),
			),
			giu.InputText(&app.selectedDllPath).Hint("Enter DLL path...").Size(400),
			giu.Spacing(),

			// Target Process
			giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 51, G: 204, B: 255, A: 255}).To(
				giu.Label("Target Process:"),
			),
			giu.Label(fmt.Sprintf("Selected: PID %d (%s)", app.selectedPID, app.selectedProcessName)),
			giu.Spacing(),

			// Injection Method
			giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 51, G: 204, B: 255, A: 255}).To(
				giu.Label("Injection Method:"),
			),
			giu.Combo("##injection_method", app.methodNames[app.injectionMethod], app.methodNames, &app.injectionMethod),
			giu.Spacing(),

			// Basic Options
			giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 255, G: 255, B: 51, A: 255}).To(
				giu.Label("Anti-Detection Options:"),
			),
			giu.Row(
				giu.Checkbox("Memory Load", &app.memoryLoad),
				giu.Checkbox("Manual Mapping", &app.manualMapping),
			),
			giu.Row(
				giu.Checkbox("Path Spoofing", &app.pathSpoofing),
				giu.Checkbox("PE Header Erasure", &app.peHeaderErasure),
			),
			giu.Spacing(),

			// Action Buttons
			giu.Style().SetColor(giu.StyleColorButton, color.RGBA{R: 51, G: 179, B: 51, A: 255}).To(
				giu.Button("INJECT DLL").Size(200, 40).OnClick(func() {
					fmt.Printf("Inject button clicked - DLL: %s, PID: %d\n", app.selectedDllPath, app.selectedPID)
				}),
			),
			giu.Spacing(),
			giu.Button("Refresh Processes").OnClick(func() {
				app.refreshProcessList()
				fmt.Printf("Process list refreshed - found %d processes\n", len(app.processes))
			}),
			giu.Spacing(),
			giu.Button("Exit").OnClick(func() {
				fmt.Println("Exit button clicked")
			}),
		),
	)
}

// buildLeftPanel builds the left panel with injection controls
func (app *Application) buildLeftPanel() giu.Widget {
	return giu.Child().Size(-1, -1).Layout(
		giu.Style().SetStyle(giu.StyleVarWindowPadding, 10, 10).To(
			giu.Column(
				// DLL File Selection
				giu.Style().SetStyle(giu.StyleVarFramePadding, 5, 5).To(
					giu.Column(
						giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 51, G: 204, B: 255, A: 255}).To(
							giu.Label("DLL File Selection"),
						),
						giu.Separator(),
						giu.Row(
							giu.InputText(&app.selectedDllPath).Size(-80).Hint("Select DLL file..."),
							giu.Button("Browse").Size(70, 0).OnClick(func() {
								// Simple file path input for now - giu file dialog API has changed
								app.logger.Info("Browse button clicked - please enter DLL path manually")
							}),
						),
					),
				),

				giu.Spacing(),

				// Injection Method Selection
				giu.Style().SetStyle(giu.StyleVarFramePadding, 5, 5).To(
					giu.Column(
						giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 51, G: 204, B: 255, A: 255}).To(
							giu.Label("Injection Method"),
						),
						giu.Separator(),
						giu.Combo("##injection_method", app.methodNames[app.injectionMethod], app.methodNames, &app.injectionMethod).Size(-1).OnChange(func() {
							app.logger.Info("Injection method changed", zap.String("method", app.methodNames[app.injectionMethod]))
						}),
					),
				),

				giu.Spacing(),

				// Anti-Detection Options
				app.buildAntiDetectionOptions(),

				giu.Spacing(),

				// Target Process
				giu.Style().SetStyle(giu.StyleVarFramePadding, 5, 5).To(
					giu.Column(
						giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 51, G: 204, B: 255, A: 255}).To(
							giu.Label("Target Process"),
						),
						giu.Separator(),
						giu.Label(fmt.Sprintf("Selected: %s (PID: %d)", app.selectedProcessName, app.selectedPID)),
					),
				),

				giu.Spacing(),

				// Inject Button
				giu.Style().SetStyle(giu.StyleVarFramePadding, 10, 10).To(
					giu.Style().SetColor(giu.StyleColorButton, color.RGBA{R: 51, G: 179, B: 51, A: 255}).To(
						giu.Style().SetColor(giu.StyleColorButtonHovered, color.RGBA{R: 77, G: 204, B: 77, A: 255}).To(
							giu.Style().SetColor(giu.StyleColorButtonActive, color.RGBA{R: 26, G: 153, B: 26, A: 255}).To(
								giu.Button("INJECT DLL").Size(-1, 50).OnClick(app.onInjectClicked),
							),
						),
					),
				),
			),
		),
	)
}

// buildAntiDetectionOptions builds the anti-detection options section
func (app *Application) buildAntiDetectionOptions() giu.Widget {
	return giu.Style().SetStyle(giu.StyleVarFramePadding, 5, 5).To(
		giu.Column(
			giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 51, G: 204, B: 255, A: 255}).To(
				giu.Label("Anti-Detection Options"),
			),
			giu.Separator(),

			// Basic Options
			giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 255, G: 255, B: 51, A: 255}).To(
				giu.Label("Basic Options:"),
			),
			giu.Row(
				giu.Checkbox("Memory Load", &app.memoryLoad),
				giu.Checkbox("Manual Mapping", &app.manualMapping),
			),
			giu.Row(
				giu.Checkbox("Path Spoofing", &app.pathSpoofing),
				giu.Checkbox("PE Header Erasure", &app.peHeaderErasure),
			),
			giu.Row(
				giu.Checkbox("Entry Point Erase", &app.entryPointErase),
				giu.Checkbox("Invisible Memory", &app.invisibleMemory),
			),

			giu.Spacing(),

			// Advanced Options
			giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 255, G: 255, B: 51, A: 255}).To(
				giu.Label("Advanced Options:"),
			),
			giu.Row(
				giu.Checkbox("PTE Spoofing", &app.pteSpoofing),
				giu.Checkbox("VAD Manipulation", &app.vadManipulation),
			),
			giu.Row(
				giu.Checkbox("Remove VAD Node", &app.removeVADNode),
				giu.Checkbox("Thread Stack Alloc", &app.allocBehindThreadStack),
			),
			giu.Row(
				giu.Checkbox("Direct Syscalls", &app.directSyscalls),
				giu.Checkbox("Legit Process", &app.legitProcessInjection),
			),

			giu.Spacing(),

			// Enhanced Options
			giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 255, G: 255, B: 51, A: 255}).To(
				giu.Label("Enhanced Options:"),
			),
			giu.Row(
				giu.Checkbox("Randomize Allocation", &app.randomizeAllocation),
				giu.Checkbox("Delayed Execution", &app.delayedExecution),
			),
			giu.Row(
				giu.Checkbox("Multi-Stage Injection", &app.multiStageInjection),
				giu.Checkbox("Anti-Debug", &app.antiDebugTechniques),
			),
			giu.Row(
				giu.Checkbox("Process Hollowing", &app.processHollowing),
				giu.Checkbox("Thread Hijacking", &app.threadHijacking),
			),
			giu.Row(
				giu.Checkbox("Memory Fluctuation", &app.memoryFluctuation),
				giu.Checkbox("Anti-VM", &app.antiVMTechniques),
			),
		),
	)
}

// buildRightPanel builds the right panel with process list and logs
func (app *Application) buildRightPanel() giu.Widget {
	splitRatio := float32(0.6)
	return giu.SplitLayout(giu.DirectionVertical, &splitRatio,
		// Process list
		app.buildProcessList(),
		// Log console
		app.buildLogConsole(),
	)
}

// buildProcessList builds the process list section
func (app *Application) buildProcessList() giu.Widget {
	app.mu.RLock()
	processes := make([]process.ProcessEntry, len(app.processes))
	copy(processes, app.processes)
	app.mu.RUnlock()

	// Filter processes based on search text
	var filteredProcesses []process.ProcessEntry
	searchLower := strings.ToLower(app.searchText)
	for _, proc := range processes {
		if searchLower == "" ||
			strings.Contains(strings.ToLower(proc.Name), searchLower) ||
			strings.Contains(strings.ToLower(proc.Executable), searchLower) ||
			strings.Contains(strconv.FormatInt(int64(proc.PID), 10), searchLower) {
			filteredProcesses = append(filteredProcesses, proc)
		}
	}

	return giu.Child().Size(-1, -1).Layout(
		giu.Style().SetStyle(giu.StyleVarWindowPadding, 10, 10).To(
			giu.Column(
				giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 51, G: 204, B: 255, A: 255}).To(
					giu.Label("Process List"),
				),
				giu.Separator(),
				giu.Row(
					giu.InputText(&app.searchText).Size(-80).Hint("Search processes..."),
					giu.Button("Refresh").Size(70, 0).OnClick(func() {
						app.refreshProcessList()
					}),
				),
				giu.Spacing(),
				app.buildProcessTable(filteredProcesses),
			),
		),
	)
}

// buildProcessTable builds the process table
func (app *Application) buildProcessTable(processes []process.ProcessEntry) giu.Widget {
	// Limit the number of processes shown to improve performance
	maxProcesses := 50
	if len(processes) > maxProcesses {
		processes = processes[:maxProcesses]
	}

	// Create a simple list instead of a complex table
	var processWidgets []giu.Widget

	// Header
	processWidgets = append(processWidgets,
		giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 255, G: 255, B: 51, A: 255}).To(
			giu.Label("PID | Process Name | Executable | Action"),
		),
		giu.Separator(),
	)

	// Process rows
	for _, proc := range processes {
		proc := proc // Capture for closure
		isSelected := proc.PID == app.selectedPID

		// Truncate long executable paths
		execPath := proc.Executable
		if len(execPath) > 40 {
			execPath = "..." + execPath[len(execPath)-37:]
		}

		// Create a formatted string for the process info
		processInfo := fmt.Sprintf("%d | %s | %s", proc.PID, proc.Name, execPath)

		var rowWidget giu.Widget = giu.Row(
			giu.Label(processInfo),
			giu.Button("Select").OnClick(func() {
				app.selectedPID = proc.PID
				app.selectedProcessName = proc.Name
				app.logger.Info("Process selected", zap.String("name", proc.Name), zap.Int32("pid", proc.PID))
			}),
		)

		if isSelected {
			rowWidget = giu.Style().SetColor(giu.StyleColorChildBg, color.RGBA{R: 51, G: 179, B: 51, A: 77}).To(rowWidget)
		}

		processWidgets = append(processWidgets, rowWidget)
	}

	return giu.Column(processWidgets...)
}

// buildLogConsole builds the log console section
func (app *Application) buildLogConsole() giu.Widget {
	app.mu.RLock()
	logText := app.logText
	app.mu.RUnlock()

	return giu.Child().Size(-1, -1).Layout(
		giu.Style().SetStyle(giu.StyleVarWindowPadding, 10, 10).To(
			giu.Column(
				giu.Row(
					giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 51, G: 204, B: 255, A: 255}).To(
						giu.Label("Console Logs"),
					),
					giu.Button("Clear").OnClick(func() {
						app.mu.Lock()
						app.logLines = nil
						app.logText = ""
						app.mu.Unlock()
						app.logger.Info("Logs cleared")
					}),
				),
				giu.Separator(),
				giu.Style().SetColor(giu.StyleColorFrameBg, color.RGBA{R: 26, G: 26, B: 26, A: 255}).To(
					giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 51, G: 255, B: 51, A: 255}).To(
						giu.InputTextMultiline(&logText).Size(-1, -1).Flags(giu.InputTextFlagsReadOnly),
					),
				),
			),
		),
	)
}

// buildDialogs builds all the dialog windows
func (app *Application) buildDialogs() {
	// About dialog
	if app.showAboutDialog {
		giu.PopupModal("About DLL Injector").IsOpen(&app.showAboutDialog).Layout(
			giu.Column(
				giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 51, G: 204, B: 255, A: 255}).To(
					giu.Label("DLL Injector v1.0.0"),
				),
				giu.Separator(),
				giu.Label("An advanced DLL injection tool with multiple"),
				giu.Label("injection methods and anti-detection features."),
				giu.Spacing(),
				giu.Label("© 2023-2024 DLL Injector Team"),
				giu.Spacing(),
				giu.Button("Visit GitHub").OnClick(func() {
					url := "https://github.com/whispin/dll-injector"
					if err := openURL(url); err != nil {
						app.logger.Error("Failed to open URL", zap.String("url", url), zap.Error(err))
					} else {
						app.logger.Info("Opening project homepage", zap.String("url", url))
					}
				}),
				giu.Spacing(),
				giu.Button("Close").OnClick(func() {
					app.showAboutDialog = false
				}),
			),
		)
	}

	// Help dialog
	if app.showHelpDialog {
		giu.PopupModal("Help").IsOpen(&app.showHelpDialog).Layout(
			giu.Column(
				giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 51, G: 204, B: 255, A: 255}).To(
					giu.Label("DLL Injector Help"),
				),
				giu.Separator(),
				giu.Label("1. Select a DLL file to inject"),
				giu.Label("2. Choose an injection method"),
				giu.Label("3. Configure anti-detection options"),
				giu.Label("4. Select a target process"),
				giu.Label("5. Click 'INJECT DLL' to perform injection"),
				giu.Spacing(),
				giu.Label("For more information, visit:"),
				giu.Label("https://github.com/whispin/dll-injector"),
				giu.Spacing(),
				giu.Button("Close").OnClick(func() {
					app.showHelpDialog = false
				}),
			),
		)
	}

	// Confirmation dialog
	if app.showConfirmDialog {
		giu.PopupModal("Confirm Injection").IsOpen(&app.showConfirmDialog).Layout(
			giu.Column(
				giu.Label(app.confirmDialogText),
				giu.Spacing(),
				giu.Row(
					giu.Button("Inject").OnClick(func() {
						app.showConfirmDialog = false
						app.performInjection()
					}),
					giu.Button("Cancel").OnClick(func() {
						app.showConfirmDialog = false
					}),
				),
			),
		)
	}

	// Progress dialog
	if app.showProgressDialog {
		giu.PopupModal("Injecting DLL").IsOpen(&app.showProgressDialog).Layout(
			giu.Column(
				giu.Label(app.progressText),
				giu.Spacing(),
				giu.ProgressBar(0.0).Size(-1, 0), // Indeterminate progress
			),
		)
	}

	// Success dialog
	if app.showSuccessDialog {
		giu.PopupModal("Injection Successful").IsOpen(&app.showSuccessDialog).Layout(
			giu.Column(
				giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 51, G: 255, B: 51, A: 255}).To(
					giu.Label("Injection Successful!"),
				),
				giu.Separator(),
				giu.Label(app.successText),
				giu.Spacing(),
				giu.Button("Close").OnClick(func() {
					app.showSuccessDialog = false
				}),
			),
		)
	}
}

// onInjectClicked handles the inject button click
func (app *Application) onInjectClicked() {
	if app.selectedDllPath == "" {
		app.logger.Error("No DLL file selected")
		return
	}

	if app.selectedPID <= 0 {
		app.logger.Error("No target process selected")
		return
	}

	app.confirmDialogText = fmt.Sprintf(
		"Are you sure you want to inject:\n%s\n\nInto process:\n%s (PID: %d)\n\nUsing method:\n%s",
		filepath.Base(app.selectedDllPath),
		app.selectedProcessName,
		app.selectedPID,
		app.methodNames[app.injectionMethod],
	)
	app.showConfirmDialog = true
}

// performInjection performs the actual DLL injection
func (app *Application) performInjection() {
	app.progressText = "Preparing injection..."
	app.showProgressDialog = true

	go func() {
		defer func() {
			app.showProgressDialog = false
		}()

		app.logger.Info("Starting DLL injection",
			zap.String("DLL", app.selectedDllPath),
			zap.String("Process", app.selectedProcessName),
			zap.Int32("PID", app.selectedPID),
			zap.String("Method", app.methodNames[app.injectionMethod]),
		)

		// Create injector instance
		loggerAdapter := &LoggerAdapter{logger: app.logger}
		inj := injector.NewInjector(app.selectedDllPath, uint32(app.selectedPID), loggerAdapter)

		// Set injection method
		inj.SetMethod(injector.InjectionMethod(app.injectionMethod))

		// Set anti-detection options
		options := injector.BypassOptions{
			MemoryLoad:            app.memoryLoad,
			ErasePEHeader:         app.peHeaderErasure,
			EraseEntryPoint:       app.entryPointErase,
			ManualMapping:         app.manualMapping,
			InvisibleMemory:       app.invisibleMemory,
			PathSpoofing:          app.pathSpoofing,
			LegitProcessInjection: app.legitProcessInjection,
			PTESpoofing:           app.pteSpoofing,
			VADManipulation:       app.vadManipulation,
			RemoveVADNode:         app.removeVADNode,
			ThreadStackAllocation: app.allocBehindThreadStack,
			DirectSyscalls:        app.directSyscalls,
		}
		inj.SetBypassOptions(options)

		// Set enhanced options
		enhancedOptions := injector.EnhancedBypassOptions{
			BypassOptions:        options,
			RandomizeAllocation:  app.randomizeAllocation,
			DelayedExecution:     app.delayedExecution,
			MultiStageInjection:  app.multiStageInjection,
			AntiDebugTechniques:  app.antiDebugTechniques,
			ProcessHollowing:     app.processHollowing,
			AtomBombing:          app.atomBombing,
			DoppelgangingProcess: app.doppelgangingProcess,
			GhostWriting:         app.ghostWriting,
			ModuleStomping:       app.moduleStomping,
			ThreadHijacking:      app.threadHijacking,
			APCQueueing:          app.apcQueueing,
			MemoryFluctuation:    app.memoryFluctuation,
			AntiVMTechniques:     app.antiVMTechniques,
			ProcessMirroring:     app.processMirroring,
			StealthyThreads:      app.stealthyThreads,
		}
		inj.SetEnhancedBypassOptions(enhancedOptions)

		// Perform injection
		err := inj.Inject()

		if err != nil {
			app.logger.Error("Injection failed", zap.Error(err))
		} else {
			app.logger.Info("Injection successful")
			app.successText = fmt.Sprintf(
				"DLL: %s\nProcess: %s (PID: %d)\nMethod: %s",
				filepath.Base(app.selectedDllPath),
				app.selectedProcessName,
				app.selectedPID,
				app.methodNames[app.injectionMethod],
			)
			app.showSuccessDialog = true
		}
	}()
}

// openURL opens a URL in the default browser
func openURL(url string) error {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start", url}
	case "darwin":
		cmd = "open"
		args = []string{url}
	default: // "linux", "freebsd", "openbsd", "netbsd"
		cmd = "xdg-open"
		args = []string{url}
	}

	return exec.Command(cmd, args...).Start()
}