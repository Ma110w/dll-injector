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
	showAboutDialog      bool
	showHelpDialog       bool
	showConfirmDialog    bool
	showProgressDialog   bool
	showSuccessDialog    bool
	showProcessDialog    bool  // New: Process selection dialog
	confirmDialogText    string
	progressText         string
	successText          string
	selectedTab          int32 // 0=Basic, 1=Advanced, 2=Preset
	processSearchText    string // New: Search text for process dialog

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
	// Main window with exact layout matching the screenshot
	giu.SingleWindow().Layout(
		giu.Style().SetStyle(giu.StyleVarWindowPadding, 15, 15).To(
			giu.Column(
				// Top row: DLL File and Target Process
				app.buildTopRow(),
				giu.Spacing(),
				giu.Spacing(),

				// Injection Method Section
				app.buildInjectionMethodSection(),
				giu.Spacing(),
				giu.Spacing(),

				// Anti-Detection Options Section
				app.buildAntiDetectionSection(),
				giu.Spacing(),
				giu.Spacing(),

				// Inject Button
				app.buildInjectButton(),
				giu.Spacing(),

				// Console Logs Section
				app.buildConsoleLogsSection(),
			),
		),
	)

	// Render dialogs
	app.buildProcessSelectionDialog()
}

// buildTopRow builds the top row with DLL File and Target Process
func (app *Application) buildTopRow() giu.Widget {
	processText := "No Process Selected"
	if app.selectedPID > 0 {
		processText = fmt.Sprintf("PID: %d - %s", app.selectedPID, app.selectedProcessName)
	}

	return giu.Row(
		// Left side - DLL File
		giu.Column(
			giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 170, G: 170, B: 170, A: 255}).To(
				giu.Label("DLL File:"),
			),
			giu.Row(
				giu.Style().SetColor(giu.StyleColorFrameBg, color.RGBA{R: 50, G: 50, B: 50, A: 255}).To(
					giu.InputText(&app.selectedDllPath).Hint("Select DLL file path...").Size(400),
				),
				giu.Style().SetColor(giu.StyleColorButton, color.RGBA{R: 80, G: 80, B: 80, A: 255}).To(
					giu.Button("📁").Size(30, 0).OnClick(func() {
						fmt.Println("Browse DLL file")
					}),
				),
			),
		),

		giu.Dummy(50, 0), // Spacer

		// Right side - Target Process
		giu.Column(
			giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 170, G: 170, B: 170, A: 255}).To(
				giu.Label("Target Process:"),
			),
			giu.Row(
				giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 140, G: 140, B: 140, A: 255}).To(
					giu.Label(processText),
				),
				giu.Style().SetColor(giu.StyleColorButton, color.RGBA{R: 80, G: 80, B: 80, A: 255}).To(
					giu.Button("Select Process").OnClick(func() {
						fmt.Println("Opening process selection dialog")
						app.refreshProcessList() // Refresh process list before showing dialog
						app.showProcessDialog = true
					}),
				),
			),
		),
	)
}

// buildInjectionMethodSection builds the injection method selection section
func (app *Application) buildInjectionMethodSection() giu.Widget {
	return giu.Column(
		giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 170, G: 170, B: 170, A: 255}).To(
			giu.Label("Injection Method:"),
		),
		giu.Spacing(),
		// Single row with all 6 radio buttons
		giu.Row(
			giu.Style().SetColor(giu.StyleColorCheckMark, color.RGBA{R: 0, G: 122, B: 204, A: 255}).To(
				giu.RadioButton("Standard Injection", app.injectionMethod == 0).OnChange(func() {
					app.injectionMethod = 0
					fmt.Println("✓ Injection method selected: Standard Injection")
				}),
			),
			giu.RadioButton("SetWindowsHookEx", app.injectionMethod == 1).OnChange(func() {
				app.injectionMethod = 1
				fmt.Println("✓ Injection method selected: SetWindowsHookEx")
			}),
			giu.RadioButton("QueueUserAPC", app.injectionMethod == 2).OnChange(func() {
				app.injectionMethod = 2
				fmt.Println("✓ Injection method selected: QueueUserAPC")
			}),
			giu.RadioButton("Early Bird", app.injectionMethod == 3).OnChange(func() {
				app.injectionMethod = 3
				fmt.Println("✓ Injection method selected: Early Bird")
			}),
			giu.RadioButton("DLL Notification", app.injectionMethod == 4).OnChange(func() {
				app.injectionMethod = 4
				fmt.Println("✓ Injection method selected: DLL Notification")
			}),
			giu.RadioButton("Job Object", app.injectionMethod == 5).OnChange(func() {
				app.injectionMethod = 5
				fmt.Println("✓ Injection method selected: Job Object")
			}),
		),
	)
}

// buildAntiDetectionSection builds the anti-detection options section exactly like screenshot
func (app *Application) buildAntiDetectionSection() giu.Widget {
	return giu.Column(
		// Header with dropdown arrow
		giu.Row(
			giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 170, G: 170, B: 170, A: 255}).To(
				giu.Label("🛡️ Anti-Detection Options"),
			),
		),
		giu.Spacing(),

		// Tab buttons - exactly like screenshot
		giu.Row(
			// Basic tab (active/blue)
			giu.Style().SetColor(giu.StyleColorButton, color.RGBA{R: 0, G: 122, B: 204, A: 255}).To(
				giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 255, G: 255, B: 255, A: 255}).To(
					giu.Button("Basic").Size(60, 25).OnClick(func() {
						app.selectedTab = 0
						fmt.Println("Basic tab selected")
					}),
				),
			),
			// Advanced tab (inactive/gray)
			giu.Style().SetColor(giu.StyleColorButton, color.RGBA{R: 80, G: 80, B: 80, A: 255}).To(
				giu.Button("Advanced").Size(80, 25).OnClick(func() {
					app.selectedTab = 1
					fmt.Println("Advanced tab selected")
				}),
			),
			// Preset tab (inactive/gray)
			giu.Style().SetColor(giu.StyleColorButton, color.RGBA{R: 80, G: 80, B: 80, A: 255}).To(
				giu.Button("Preset").Size(60, 25).OnClick(func() {
					app.selectedTab = 2
					fmt.Println("Preset tab selected")
				}),
			),
		),
		giu.Spacing(),

		// Tab content in 3-column layout like screenshot
		app.buildTabContent(),
	)
}

// buildTabContent builds the content for the selected tab in 3-column layout like screenshot
func (app *Application) buildTabContent() giu.Widget {
	switch app.selectedTab {
	case 0: // Basic - exactly like screenshot
		return giu.Column(
			// First row of checkboxes
			giu.Row(
				giu.Column(
					giu.Checkbox("Memory Load", &app.memoryLoad),
				),
				giu.Dummy(120, 0), // Spacer
				giu.Column(
					giu.Checkbox("Manual Mapping", &app.manualMapping),
				),
				giu.Dummy(120, 0), // Spacer
				giu.Column(
					giu.Checkbox("Erase PE Header", &app.peHeaderErasure),
				),
			),
			giu.Spacing(),
			// Second row of checkboxes
			giu.Row(
				giu.Column(
					giu.Checkbox("Path Spoofing", &app.pathSpoofing),
				),
				giu.Dummy(120, 0), // Spacer
				giu.Column(
					giu.Checkbox("Legitimate Process", &app.legitProcessInjection),
				),
				giu.Dummy(120, 0), // Spacer
				giu.Column(
					giu.Checkbox("Erase Entry Point", &app.entryPointErase),
				),
			),
		)
	case 1: // Advanced
		return giu.Column(
			giu.Row(
				giu.Column(
					giu.Checkbox("PTE Spoofing", &app.pteSpoofing),
				),
				giu.Dummy(120, 0),
				giu.Column(
					giu.Checkbox("VAD Manipulation", &app.vadManipulation),
				),
				giu.Dummy(120, 0),
				giu.Column(
					giu.Checkbox("Remove VAD Node", &app.removeVADNode),
				),
			),
			giu.Spacing(),
			giu.Row(
				giu.Column(
					giu.Checkbox("Thread Stack Alloc", &app.allocBehindThreadStack),
				),
				giu.Dummy(120, 0),
				giu.Column(
					giu.Checkbox("Direct Syscalls", &app.directSyscalls),
				),
				giu.Dummy(120, 0),
				giu.Column(
					giu.Checkbox("Process Hollowing", &app.processHollowing),
				),
			),
		)
	case 2: // Preset
		return giu.Column(
			giu.Row(
				giu.Button("Stealth Mode").Size(120, 30).OnClick(func() {
					app.memoryLoad = true
					app.manualMapping = true
					app.peHeaderErasure = true
					app.pathSpoofing = true
					fmt.Println("✓ Stealth mode preset applied")
				}),
				giu.Button("Maximum Evasion").Size(120, 30).OnClick(func() {
					app.memoryLoad = true
					app.manualMapping = true
					app.peHeaderErasure = true
					app.pathSpoofing = true
					app.pteSpoofing = true
					app.vadManipulation = true
					app.directSyscalls = true
					fmt.Println("✓ Maximum evasion preset applied")
				}),
				giu.Button("Clear All").Size(120, 30).OnClick(func() {
					app.clearAllOptions()
					fmt.Println("✓ All options cleared")
				}),
			),
		)
	default:
		return giu.Label("Unknown tab")
	}
}

// buildInjectButton builds the main inject button exactly like screenshot
func (app *Application) buildInjectButton() giu.Widget {
	return giu.Style().SetColor(giu.StyleColorButton, color.RGBA{R: 0, G: 122, B: 204, A: 255}).To(
		giu.Style().SetColor(giu.StyleColorButtonHovered, color.RGBA{R: 0, G: 140, B: 230, A: 255}).To(
			giu.Style().SetColor(giu.StyleColorButtonActive, color.RGBA{R: 0, G: 100, B: 180, A: 255}).To(
				giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 255, G: 255, B: 255, A: 255}).To(
					giu.Button("Inject").Size(-1, 45).OnClick(func() {
						app.onInjectClickedSimple()
					}),
				),
			),
		),
	)
}

// buildConsoleLogsSection builds the console logs section exactly like screenshot
func (app *Application) buildConsoleLogsSection() giu.Widget {
	app.mu.RLock()
	logText := app.logText
	app.mu.RUnlock()

	return giu.Column(
		// Header row with Console Logs and home button
		giu.Row(
			giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 170, G: 170, B: 170, A: 255}).To(
				giu.Label("Console Logs"),
			),
			giu.Dummy(-1, 0), // Push button to right
			giu.Style().SetColor(giu.StyleColorButton, color.RGBA{R: 80, G: 80, B: 80, A: 255}).To(
				giu.Button("🏠").Size(25, 25).OnClick(func() {
					fmt.Println("Home button clicked")
				}),
			),
		),
		giu.Spacing(),
		// Console text area with dark background
		giu.Style().SetColor(giu.StyleColorFrameBg, color.RGBA{R: 25, G: 25, B: 25, A: 255}).To(
			giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 180, G: 180, B: 180, A: 255}).To(
				giu.InputTextMultiline(&logText).Size(-1, 120).Flags(giu.InputTextFlagsReadOnly),
			),
		),
	)
}

// clearAllOptions clears all anti-detection options
func (app *Application) clearAllOptions() {
	app.memoryLoad = false
	app.peHeaderErasure = false
	app.entryPointErase = false
	app.manualMapping = false
	app.invisibleMemory = false
	app.pathSpoofing = false
	app.legitProcessInjection = false
	app.pteSpoofing = false
	app.vadManipulation = false
	app.removeVADNode = false
	app.allocBehindThreadStack = false
	app.directSyscalls = false
	app.processHollowing = false
}

// onInjectClicked handles the inject button click
func (app *Application) onInjectClickedSimple() {
	if app.selectedDllPath == "" {
		app.addLogLine("❌ Error: No DLL file selected")
		fmt.Println("Error: No DLL file selected")
		return
	}

	if app.selectedPID <= 0 {
		app.addLogLine("❌ Error: No target process selected")
		fmt.Println("Error: No target process selected")
		return
	}

	methodName := app.methodNames[app.injectionMethod]
	app.addLogLine(fmt.Sprintf("🚀 Starting injection: %s -> PID %d using %s",
		filepath.Base(app.selectedDllPath), app.selectedPID, methodName))

	fmt.Printf("Injection started: DLL=%s, PID=%d, Method=%s\n",
		app.selectedDllPath, app.selectedPID, methodName)
}

// buildProcessSelectionDialog builds the process selection dialog
func (app *Application) buildProcessSelectionDialog() {
	if !app.showProcessDialog {
		return
	}

	giu.PopupModal("Select Target Process").IsOpen(&app.showProcessDialog).Layout(
		giu.Column(
			// Search section
			giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 170, G: 170, B: 170, A: 255}).To(
				giu.Label("Search Processes:"),
			),
			giu.Row(
				giu.Style().SetColor(giu.StyleColorFrameBg, color.RGBA{R: 50, G: 50, B: 50, A: 255}).To(
					giu.InputText(&app.processSearchText).Hint("Type to search processes...").Size(600),
				),
				giu.Style().SetColor(giu.StyleColorButton, color.RGBA{R: 0, G: 122, B: 204, A: 255}).To(
					giu.Button("Refresh").Size(80, 0).OnClick(func() {
						app.refreshProcessList()
						fmt.Println("Process list refreshed")
					}),
				),
			),
			giu.Spacing(),

			// Process list
			giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 170, G: 170, B: 170, A: 255}).To(
				giu.Label("Available Processes:"),
			),
			giu.Separator(),

			// Process table in a child window for scrolling
			giu.Child().Size(-1, 400).Layout(
				app.buildProcessTable(),
			),

			giu.Spacing(),
			// Dialog buttons
			giu.Row(
				giu.Style().SetColor(giu.StyleColorButton, color.RGBA{R: 80, G: 80, B: 80, A: 255}).To(
					giu.Button("Cancel").Size(100, 30).OnClick(func() {
						app.showProcessDialog = false
						app.processSearchText = "" // Clear search
					}),
				),
			),
		),
	)
}

// buildProcessTable builds the process table for the dialog
func (app *Application) buildProcessTable() giu.Widget {
	app.mu.RLock()
	processes := make([]process.ProcessEntry, len(app.processes))
	copy(processes, app.processes)
	app.mu.RUnlock()

	// Filter processes based on search text
	var filteredProcesses []process.ProcessEntry
	searchLower := strings.ToLower(app.processSearchText)
	for _, proc := range processes {
		if searchLower == "" ||
			strings.Contains(strings.ToLower(proc.Name), searchLower) ||
			strings.Contains(strings.ToLower(proc.Executable), searchLower) ||
			strings.Contains(strconv.FormatInt(int64(proc.PID), 10), searchLower) {
			filteredProcesses = append(filteredProcesses, proc)
		}
	}

	// Limit the number of processes shown to improve performance
	maxProcesses := 100
	if len(filteredProcesses) > maxProcesses {
		filteredProcesses = filteredProcesses[:maxProcesses]
	}

	var processWidgets []giu.Widget

	// Header
	processWidgets = append(processWidgets,
		giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 0, G: 122, B: 204, A: 255}).To(
			giu.Row(
				giu.Label("PID"),
				giu.Dummy(60, 0),
				giu.Label("Process Name"),
				giu.Dummy(150, 0),
				giu.Label("Executable Path"),
				giu.Dummy(200, 0),
				giu.Label("Action"),
			),
		),
		giu.Separator(),
	)

	// Process rows
	for _, proc := range filteredProcesses {
		proc := proc // Capture for closure
		isSelected := proc.PID == app.selectedPID

		// Truncate long executable paths
		execPath := proc.Executable
		if len(execPath) > 60 {
			execPath = "..." + execPath[len(execPath)-57:]
		}

		// Style for selected row
		var rowStyle giu.Widget
		if isSelected {
			rowStyle = giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 0, G: 255, B: 0, A: 255}).To(
				giu.Row(
					giu.Label(fmt.Sprintf("%d", proc.PID)),
					giu.Dummy(60, 0),
					giu.Label(proc.Name),
					giu.Dummy(150, 0),
					giu.Label(execPath),
					giu.Dummy(200, 0),
					giu.Style().SetColor(giu.StyleColorButton, color.RGBA{R: 0, G: 122, B: 204, A: 255}).To(
						giu.Button("✓ Selected").OnClick(func() {
							app.selectedPID = proc.PID
							app.selectedProcessName = proc.Name
							app.showProcessDialog = false
							app.processSearchText = "" // Clear search
							app.addLogLine(fmt.Sprintf("✓ Process selected: %s (PID: %d)", proc.Name, proc.PID))
							fmt.Printf("Process selected: %s (PID: %d)\n", proc.Name, proc.PID)
						}),
					),
				),
			)
		} else {
			rowStyle = giu.Row(
				giu.Label(fmt.Sprintf("%d", proc.PID)),
				giu.Dummy(60, 0),
				giu.Label(proc.Name),
				giu.Dummy(150, 0),
				giu.Label(execPath),
				giu.Dummy(200, 0),
				giu.Style().SetColor(giu.StyleColorButton, color.RGBA{R: 80, G: 80, B: 80, A: 255}).To(
					giu.Button("Select").OnClick(func() {
						app.selectedPID = proc.PID
						app.selectedProcessName = proc.Name
						app.showProcessDialog = false
						app.processSearchText = "" // Clear search
						app.addLogLine(fmt.Sprintf("✓ Process selected: %s (PID: %d)", proc.Name, proc.PID))
						fmt.Printf("Process selected: %s (PID: %d)\n", proc.Name, proc.PID)
					}),
				),
			)
		}

		processWidgets = append(processWidgets, rowStyle)
	}

	// Show count info
	processWidgets = append(processWidgets,
		giu.Spacing(),
		giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 150, G: 150, B: 150, A: 255}).To(
			giu.Label(fmt.Sprintf("Showing %d of %d processes", len(filteredProcesses), len(processes))),
		),
	)

	return giu.Column(processWidgets...)
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

// buildRightPanel builds the right panel with process list and logs (legacy - not used in current layout)
// This function is kept for potential future use but not currently called

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