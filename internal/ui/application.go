package ui

import (
	"fmt"
	"image/color"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/AllenDang/giu"
	"github.com/whispin/dll-injector/internal/injector"
	"github.com/whispin/dll-injector/internal/process"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/sys/windows"
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
	showProcessDialog  bool // Process selection dialog
	confirmDialogText  string
	progressText       string
	successText        string
	selectedTab        int32  // 0=Basic, 1=Advanced, 2=Preset
	processSearchText  string // Search text for process dialog

	// UI update channels for thread-safe UI updates
	injectionResultChan chan InjectionResult
	logMessageChan      chan string
	uiUpdateChan        chan func()

	// Mutex for thread safety
	mu sync.RWMutex
}

// InjectionResult represents the result of an injection operation
type InjectionResult struct {
	Success bool
	Error   error
	Message string
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
			"CryoBird (Job Object)",
		},
		injectionResultChan: make(chan InjectionResult, 10), // 增加缓冲大小
		logMessageChan:      make(chan string, 100),         // 日志消息通道
		uiUpdateChan:        make(chan func(), 50),          // UI更新通道
	}

	// Initialize logger
	app.setupLogger()

	// Initialize process info
	app.refreshProcessList()

	return app
}

// isOptionCompatible checks if an anti-detection option is compatible with the current injection method
func (app *Application) isOptionCompatible(option string) bool {
	method := app.injectionMethod

	// Comprehensive compatibility matrix based on technical analysis
	// Methods: 0=Standard, 1=SetWindowsHookEx, 2=QueueUserAPC, 3=EarlyBirdAPC, 4=DllNotification, 5=CryoBird
	switch option {
	case "memory_load":
		// ❌ SetWindowsHookEx, DllNotification (require Windows loader)
		return method != 1 && method != 4

	case "manual_mapping":
		// ❌ SetWindowsHookEx, DllNotification (require Windows loader)
		return method != 1 && method != 4

	case "pe_header_erasure":
		// ⚠️ Standard (works but may affect stability), ❌ SetWindowsHookEx, DllNotification
		// ✅ QueueUserAPC, EarlyBirdAPC, CryoBird
		return method == 2 || method == 3 || method == 5

	case "entry_point_erasure":
		// ⚠️ Standard (works but may affect stability), ❌ SetWindowsHookEx, DllNotification
		// ✅ QueueUserAPC, EarlyBirdAPC, CryoBird
		return method == 2 || method == 3 || method == 5

	case "invisible_memory":
		// ❌ SetWindowsHookEx, ⚠️ DllNotification
		// ✅ All memory-capable methods
		return method != 1

	case "path_spoofing":
		// ❌ Memory-only methods (QueueUserAPC, EarlyBirdAPC, CryoBird)
		// ✅ Disk-based methods only
		return method == 0 || method == 1 || method == 4

	case "legit_process":
		// ✅ Standard, SetWindowsHookEx, DllNotification
		// ⚠️ Memory-based methods (limited compatibility)
		return method == 0 || method == 1 || method == 4

	case "pte_spoofing":
		// ❌ SetWindowsHookEx, ⚠️ DllNotification
		// ✅ Memory allocation methods
		return method != 1 && method != 4

	case "vad_manipulation":
		// ❌ SetWindowsHookEx, ⚠️ DllNotification
		// ✅ Memory allocation methods
		return method != 1 && method != 4

	case "remove_vad_node":
		// ❌ SetWindowsHookEx, ⚠️ DllNotification
		// ✅ Memory allocation methods
		return method != 1 && method != 4

	case "thread_stack_allocation":
		// ❌ SetWindowsHookEx
		// ✅ All thread-based methods
		return method != 1

	case "direct_syscalls":
		// ✅ Compatible with all methods
		return true

	case "skip_dllmain":
		// ✅ All methods, ⚠️ SetWindowsHookEx (limited effectiveness)
		return true

	// Enhanced options compatibility
	case "randomize_allocation", "delayed_execution", "multi_stage_injection":
		// Advanced options work best with memory-based methods
		return method != 1 && method != 4

	case "anti_debug", "anti_vm":
		// Detection evasion works with all methods
		return true

	case "process_hollowing", "thread_hijacking":
		// Advanced techniques require memory manipulation
		return method == 0 || method == 2 || method == 3 || method == 5

	case "memory_fluctuation":
		// Memory manipulation technique
		return method != 1 && method != 4

	case "atom_bombing":
		// ❌ SetWindowsHookEx (incompatible with atom table manipulation)
		// ✅ Methods that support atom table access
		return method != 1

	case "doppelganging_process":
		// ❌ SetWindowsHookEx, DllNotification (require process creation control)
		// ✅ Methods with process creation capabilities
		return method == 0 || method == 3 || method == 5

	case "ghost_writing":
		// ❌ SetWindowsHookEx (requires direct memory access)
		// ✅ Memory manipulation methods
		return method != 1

	case "module_stomping":
		// ❌ SetWindowsHookEx (requires module manipulation)
		// ✅ Methods with memory control
		return method != 1

	case "apc_queueing":
		// ✅ APC-based methods, ❌ Hook-based methods
		return method == 2 || method == 3 || method == 5

	case "process_mirroring":
		// ❌ SetWindowsHookEx, DllNotification (require process control)
		// ✅ Advanced memory methods
		return method == 0 || method == 2 || method == 3 || method == 5

	case "stealthy_threads":
		// ❌ SetWindowsHookEx (conflicts with thread management)
		// ✅ Thread-based methods
		return method != 1

	default:
		// Unknown options are assumed compatible for safety
		return true
	}
}

// checkMutualExclusivity checks if enabling an option would conflict with currently enabled options
func (app *Application) checkMutualExclusivity(option string) (bool, string) {
	switch option {
	case "memory_load":
		if app.pathSpoofing {
			return false, "Memory Load is incompatible with Path Spoofing (memory-only vs disk-based)"
		}
		if app.manualMapping {
			return false, "Memory Load already includes Manual Mapping functionality"
		}

	case "manual_mapping":
		if app.memoryLoad {
			return false, "Manual Mapping is redundant when Memory Load is enabled"
		}
		if app.pathSpoofing {
			return false, "Manual Mapping is incompatible with Path Spoofing (memory-only vs disk-based)"
		}

	case "path_spoofing":
		if app.memoryLoad {
			return false, "Path Spoofing is incompatible with Memory Load (disk-based vs memory-only)"
		}
		if app.manualMapping {
			return false, "Path Spoofing is incompatible with Manual Mapping (disk-based vs memory-only)"
		}

	case "pe_header_erasure":
		if app.pathSpoofing {
			return false, "PE Header Erasure may conflict with disk-based Path Spoofing"
		}

	case "entry_point_erasure":
		if app.pathSpoofing {
			return false, "Entry Point Erasure may conflict with disk-based Path Spoofing"
		}

	case "vad_manipulation":
		if app.removeVADNode {
			return false, "VAD Manipulation conflicts with Remove VAD Node (overlapping functionality)"
		}
		if app.pteSpoofing {
			return false, "VAD Manipulation may conflict with PTE Spoofing (both modify memory structures)"
		}

	case "remove_vad_node":
		if app.vadManipulation {
			return false, "Remove VAD Node conflicts with VAD Manipulation (overlapping functionality)"
		}

	case "pte_spoofing":
		if app.vadManipulation {
			return false, "PTE Spoofing may conflict with VAD Manipulation (both modify memory structures)"
		}

	// Enhanced options mutual exclusivity
	case "process_hollowing":
		if app.threadHijacking {
			return false, "Process Hollowing and Thread Hijacking are alternative techniques"
		}
		if app.doppelgangingProcess {
			return false, "Process Hollowing and Process Doppelganging are alternative process manipulation techniques"
		}

	case "thread_hijacking":
		if app.processHollowing {
			return false, "Thread Hijacking and Process Hollowing are alternative techniques"
		}

	case "atom_bombing":
		if app.apcQueueing {
			return false, "Atom Bombing and APC Queueing may conflict (both use APC mechanisms)"
		}

	case "doppelganging_process":
		if app.processHollowing {
			return false, "Process Doppelganging and Process Hollowing are alternative process manipulation techniques"
		}
		if app.processMirroring {
			return false, "Process Doppelganging and Process Mirroring are alternative process techniques"
		}

	case "ghost_writing":
		if app.moduleStomping {
			return false, "Ghost Writing and Module Stomping are alternative memory manipulation techniques"
		}

	case "module_stomping":
		if app.ghostWriting {
			return false, "Module Stomping and Ghost Writing are alternative memory manipulation techniques"
		}

	case "apc_queueing":
		if app.atomBombing {
			return false, "APC Queueing and Atom Bombing may conflict (both use APC mechanisms)"
		}

	case "process_mirroring":
		if app.doppelgangingProcess {
			return false, "Process Mirroring and Process Doppelganging are alternative process techniques"
		}
	}

	return true, ""
}

// getOptionWarnings returns warnings for potentially problematic combinations
func (app *Application) getOptionWarnings(option string) []string {
	var warnings []string

	switch option {
	case "pe_header_erasure":
		if app.injectionMethod == 0 { // Standard
			warnings = append(warnings, "PE Header Erasure with Standard injection may affect stability")
		}

	case "entry_point_erasure":
		if app.injectionMethod == 0 { // Standard
			warnings = append(warnings, "Entry Point Erasure with Standard injection may affect stability")
		}

	case "invisible_memory":
		if app.injectionMethod == 4 { // DllNotification
			warnings = append(warnings, "Invisible Memory has limited compatibility with DLL Notification")
		}

	case "legit_process":
		if app.injectionMethod == 2 || app.injectionMethod == 3 || app.injectionMethod == 5 {
			warnings = append(warnings, "Legitimate Process Injection has limited compatibility with memory-based methods")
		}

	case "skip_dllmain":
		warnings = append(warnings, "Skipping DllMain may prevent proper DLL initialization")

	case "vad_manipulation":
		if app.pteSpoofing {
			warnings = append(warnings, "Using both VAD Manipulation and PTE Spoofing may be excessive")
		}
	}

	return warnings
}

// buildCompatibleCheckbox creates a checkbox that is enabled/disabled based on injection method compatibility
func (app *Application) buildCompatibleCheckbox(label string, option string, value *bool) giu.Widget {
	return app.buildEnhancedCheckbox(label, option, value, false)
}

// buildEnhancedCheckbox creates an advanced checkbox with full compatibility and mutual exclusivity checking
func (app *Application) buildEnhancedCheckbox(label string, option string, value *bool, showWarnings bool) giu.Widget {
	isCompatible := app.isOptionCompatible(option)
	isExclusive, exclusivityReason := app.checkMutualExclusivity(option)
	warnings := app.getOptionWarnings(option)

	// Build tooltip content
	var tooltipLines []string

	if !isCompatible {
		tooltipLines = append(tooltipLines, fmt.Sprintf("❌ %s is not compatible with %s injection", label, app.methodNames[app.injectionMethod]))
		// Force disable incompatible options
		*value = false
	} else if !isExclusive {
		tooltipLines = append(tooltipLines, fmt.Sprintf("🚫 %s", exclusivityReason))
		// Force disable mutually exclusive options
		*value = false
	} else {
		tooltipLines = append(tooltipLines, fmt.Sprintf("✅ %s is compatible with %s injection", label, app.methodNames[app.injectionMethod]))
	}

	// Add warnings to tooltip
	if showWarnings && len(warnings) > 0 {
		for _, warning := range warnings {
			tooltipLines = append(tooltipLines, fmt.Sprintf("⚠️ %s", warning))
		}
	}

	tooltip := strings.Join(tooltipLines, "\n")

	// Determine checkbox appearance and behavior
	if !isCompatible {
		// Incompatible - grayed out and disabled
		return giu.Style().
			SetColor(giu.StyleColorText, color.RGBA{R: 100, G: 100, B: 100, A: 255}).
			SetColor(giu.StyleColorCheckMark, color.RGBA{R: 100, G: 100, B: 100, A: 255}).
			SetColor(giu.StyleColorFrameBg, color.RGBA{R: 40, G: 40, B: 40, A: 255}).To(
			giu.Row(
				giu.Label(fmt.Sprintf("☐ %s", label)),
				giu.Tooltip(tooltip),
			),
		)
	} else if !isExclusive {
		// Mutually exclusive - red tinted and disabled
		return giu.Style().
			SetColor(giu.StyleColorText, color.RGBA{R: 180, G: 100, B: 100, A: 255}).
			SetColor(giu.StyleColorCheckMark, color.RGBA{R: 180, G: 100, B: 100, A: 255}).
			SetColor(giu.StyleColorFrameBg, color.RGBA{R: 50, G: 30, B: 30, A: 255}).To(
			giu.Row(
				giu.Label(fmt.Sprintf("🚫 %s", label)),
				giu.Tooltip(tooltip),
			),
		)
	} else if len(warnings) > 0 && showWarnings {
		// Compatible but with warnings - yellow tinted
		return giu.Style().
			SetColor(giu.StyleColorText, color.RGBA{R: 200, G: 180, B: 100, A: 255}).To(
			giu.Row(
				giu.Checkbox(fmt.Sprintf("⚠️ %s", label), value),
				giu.Tooltip(tooltip),
			),
		)
	} else {
		// Fully compatible - normal appearance
		return giu.Row(
			giu.Checkbox(label, value),
			giu.Tooltip(tooltip),
		)
	}
}

// buildSmartCheckbox creates a checkbox with automatic mutual exclusivity handling
func (app *Application) buildSmartCheckbox(label string, option string, value *bool) giu.Widget {
	checkbox := app.buildEnhancedCheckbox(label, option, value, true)

	// Add onChange handler to automatically handle mutual exclusivity
	if app.isOptionCompatible(option) {
		if isExclusive, _ := app.checkMutualExclusivity(option); isExclusive {
			return giu.Row(
				checkbox,
				giu.Custom(func() {
					// Handle automatic mutual exclusivity when option is enabled
					if *value {
						app.handleMutualExclusivity(option)
					}
				}),
			)
		}
	}

	return checkbox
}

// handleMutualExclusivity automatically disables conflicting options when one is enabled
func (app *Application) handleMutualExclusivity(enabledOption string) {
	switch enabledOption {
	case "memory_load":
		if app.pathSpoofing {
			app.pathSpoofing = false
			app.addLogLine("Auto-disabled Path Spoofing (incompatible with Memory Load)")
		}
		if app.manualMapping {
			app.manualMapping = false
			app.addLogLine("Auto-disabled Manual Mapping (redundant with Memory Load)")
		}

	case "manual_mapping":
		if app.pathSpoofing {
			app.pathSpoofing = false
			app.addLogLine("Auto-disabled Path Spoofing (incompatible with Manual Mapping)")
		}

	case "path_spoofing":
		if app.memoryLoad {
			app.memoryLoad = false
			app.addLogLine("Auto-disabled Memory Load (incompatible with Path Spoofing)")
		}
		if app.manualMapping {
			app.manualMapping = false
			app.addLogLine("Auto-disabled Manual Mapping (incompatible with Path Spoofing)")
		}

	case "vad_manipulation":
		if app.removeVADNode {
			app.removeVADNode = false
			app.addLogLine("Auto-disabled Remove VAD Node (conflicts with VAD Manipulation)")
		}

	case "remove_vad_node":
		if app.vadManipulation {
			app.vadManipulation = false
			app.addLogLine("Auto-disabled VAD Manipulation (conflicts with Remove VAD Node)")
		}

	case "process_hollowing":
		if app.threadHijacking {
			app.threadHijacking = false
			app.addLogLine("Auto-disabled Thread Hijacking (alternative to Process Hollowing)")
		}

	case "thread_hijacking":
		if app.processHollowing {
			app.processHollowing = false
			app.addLogLine("Auto-disabled Process Hollowing (alternative to Thread Hijacking)")
		}
	}
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

// addLogLine adds a line to the log display - thread safe version
func (app *Application) addLogLine(line string) {
	// Send log message to main thread for processing
	select {
	case app.logMessageChan <- line:
		// Successfully sent to main thread
	default:
		// Channel is full, try direct update with mutex (fallback)
		app.addLogLineImmediate(line)
	}
}

// addLogLineImmediate adds a line to the log display immediately (mutex protected)
func (app *Application) addLogLineImmediate(line string) {
	app.mu.Lock()
	defer app.mu.Unlock()

	app.logLines = append(app.logLines, line)
	if len(app.logLines) > app.maxLogLines {
		app.logLines = app.logLines[1:]
	}

	app.logText = strings.Join(app.logLines, "\n")
}

// processUIUpdates processes all pending UI updates in the main thread
func (app *Application) processUIUpdates() {
	// Process log messages
	for {
		select {
		case logMsg := <-app.logMessageChan:
			app.addLogLineImmediate(logMsg)
		default:
			goto processFuncUpdates
		}
	}

processFuncUpdates:
	// Process UI function updates
	for {
		select {
		case updateFunc := <-app.uiUpdateChan:
			updateFunc()
		default:
			return
		}
	}
}

// scheduleUIUpdate schedules a UI update function to run in the main thread
func (app *Application) scheduleUIUpdate(updateFunc func()) {
	select {
	case app.uiUpdateChan <- updateFunc:
		// Successfully scheduled
	default:
		// Channel is full, execute immediately with caution
		updateFunc()
	}
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

	// Configure fonts for emoji support after window creation
	app.setupFonts()

	app.logger.Info("Master window created, starting main loop...")

	// Add initial log entry
	app.addLogLine("DLL Injector started")
	app.addLogLine("Click 'Select Process' to choose target process")

	// Run the main loop
	wnd.Run(app.loop)

	app.logger.Info("GUI application finished")
	return nil
}

// setupFonts configures font atlas with emoji support
// This function addresses the issue where emojis display as '?' by:
// 1. Pre-registering all emoji strings used in the application
// 2. Adding Unicode-capable fonts (starting with Segoe UI Emoji for Windows)
// 3. Enabling automatic string registration for dynamic content
func (app *Application) setupFonts() {
	// Get the default font atlas
	fontAtlas := giu.Context.FontAtlas

	// Pre-register all emoji strings used in the application
	emojiStrings := []string{
		"✅", "❌", "⚠️", "🚫", "🔄", "☐",
	}

	for _, emoji := range emojiStrings {
		fontAtlas.PreRegisterString(emoji)
	}

	// Try to add Unicode-capable fonts for Windows emoji support
	if runtime.GOOS == "windows" {
		// List of fonts to try (in order of preference)
		fontCandidates := []string{
			"Segoe UI Emoji",       // Windows 10+ emoji font
			"Segoe UI Symbol",      // Windows 8.1+ symbol font
			"Arial Unicode MS",     // Microsoft Office Unicode font
			"Lucida Sans Unicode",  // Windows Unicode font
			"Tahoma",               // Windows system font with Unicode
			"Microsoft Sans Serif", // Windows system font
		}

		fontLoaded := false
		for _, fontName := range fontCandidates {
			if font := fontAtlas.AddFont(fontName, 16.0); font != nil {
				app.logger.Info("Successfully loaded Unicode font", zap.String("font", fontName))
				fontLoaded = true
				break
			}
		}

		if !fontLoaded {
			app.logger.Warn("No Unicode fonts found, emojis may display as fallback characters")
		}
	}

	// Enable automatic string registration for dynamic emoji content
	fontAtlas.AutoRegisterStrings(true)

	app.logger.Info("Font atlas configured for emoji support")
}

// Log returns the application logger
func (app *Application) Log() *zap.Logger {
	return app.logger
}

// loop is the main UI loop
func (app *Application) loop() {
	// Handle all UI updates in the main thread
	app.processUIUpdates()

	// Check for injection results from background goroutine
	select {
	case result := <-app.injectionResultChan:
		app.handleInjectionResult(result)
	default:
		// Continue with normal UI rendering
	}

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
	app.buildDialogs()
}

// handleInjectionResult handles injection results from background goroutine
func (app *Application) handleInjectionResult(result InjectionResult) {
	app.logger.Info("=== Handling injection result ===", zap.Bool("success", result.Success))

	// Always hide progress dialog first (safe - we're in main thread)
	app.showProgressDialog = false

	if result.Success {
		app.addLogLineImmediate("✅ Injection successful!")
		app.logger.Info("Setting success dialog to true")

		app.successText = result.Message
		app.showSuccessDialog = true

		app.logger.Info("Success dialog should now be visible", zap.Bool("showSuccessDialog", app.showSuccessDialog))
	} else {
		if result.Error != nil {
			app.addLogLineImmediate(fmt.Sprintf("❌ Injection failed: %v", result.Error))
			app.logger.Error("Injection failed", zap.Error(result.Error))
		} else {
			app.addLogLineImmediate("❌ Injection failed: Unknown error")
			app.logger.Error("Injection failed with unknown error")
		}
	}
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
					giu.Button("Browse").Size(80, 0).OnClick(func() {
						app.addLogLine("Opening Windows file dialog...")
						go app.openNativeFileDialog()
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
						app.addLogLine("Opening process selection...")
						app.refreshProcessList()
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
					app.addLogLine("Injection method selected: Standard Injection")
				}),
			),
			giu.RadioButton("SetWindowsHookEx", app.injectionMethod == 1).OnChange(func() {
				app.injectionMethod = 1
				app.addLogLine("Injection method selected: SetWindowsHookEx")
			}),
			giu.RadioButton("QueueUserAPC", app.injectionMethod == 2).OnChange(func() {
				app.injectionMethod = 2
				app.addLogLine("Injection method selected: QueueUserAPC")
			}),
			giu.RadioButton("Early Bird", app.injectionMethod == 3).OnChange(func() {
				app.injectionMethod = 3
				app.addLogLine("Injection method selected: Early Bird")
			}),
			giu.RadioButton("DLL Notification", app.injectionMethod == 4).OnChange(func() {
				app.injectionMethod = 4
				app.addLogLine("Injection method selected: DLL Notification")
			}),
			giu.RadioButton("CryoBird", app.injectionMethod == 5).OnChange(func() {
				app.injectionMethod = 5
				app.addLogLine("Injection method selected: CryoBird (Job Object)")
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
				giu.Label(">> Anti-Detection Options"),
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
					}),
				),
			),
			// Advanced tab (inactive/gray)
			giu.Style().SetColor(giu.StyleColorButton, color.RGBA{R: 80, G: 80, B: 80, A: 255}).To(
				giu.Button("Advanced").Size(80, 25).OnClick(func() {
					app.selectedTab = 1
				}),
			),
			// Preset tab (inactive/gray)
			giu.Style().SetColor(giu.StyleColorButton, color.RGBA{R: 80, G: 80, B: 80, A: 255}).To(
				giu.Button("Preset").Size(60, 25).OnClick(func() {
					app.selectedTab = 2
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
					app.buildCompatibleCheckbox("Memory Load", "memory_load", &app.memoryLoad),
				),
				giu.Dummy(120, 0), // Spacer
				giu.Column(
					app.buildCompatibleCheckbox("Manual Mapping", "manual_mapping", &app.manualMapping),
				),
				giu.Dummy(120, 0), // Spacer
				giu.Column(
					app.buildCompatibleCheckbox("Erase PE Header", "pe_header_erasure", &app.peHeaderErasure),
				),
			),
			giu.Spacing(),
			// Second row of checkboxes
			giu.Row(
				giu.Column(
					app.buildCompatibleCheckbox("Path Spoofing", "path_spoofing", &app.pathSpoofing),
				),
				giu.Dummy(120, 0), // Spacer
				giu.Column(
					app.buildCompatibleCheckbox("Legitimate Process", "legit_process", &app.legitProcessInjection),
				),
				giu.Dummy(120, 0), // Spacer
				giu.Column(
					app.buildCompatibleCheckbox("Erase Entry Point", "entry_point_erasure", &app.entryPointErase),
				),
			),
		)
	case 1: // Advanced
		return giu.Column(
			giu.Row(
				giu.Column(
					app.buildCompatibleCheckbox("PTE Spoofing", "pte_spoofing", &app.pteSpoofing),
				),
				giu.Dummy(120, 0),
				giu.Column(
					app.buildCompatibleCheckbox("VAD Manipulation", "vad_manipulation", &app.vadManipulation),
				),
				giu.Dummy(120, 0),
				giu.Column(
					app.buildCompatibleCheckbox("Remove VAD Node", "remove_vad_node", &app.removeVADNode),
				),
			),
			giu.Spacing(),
			giu.Row(
				giu.Column(
					app.buildCompatibleCheckbox("Thread Stack Alloc", "thread_stack_allocation", &app.allocBehindThreadStack),
				),
				giu.Dummy(120, 0),
				giu.Column(
					app.buildCompatibleCheckbox("Direct Syscalls", "direct_syscalls", &app.directSyscalls),
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
					app.addLogLine("Stealth mode preset applied")
				}),
				giu.Button("Maximum Evasion").Size(120, 30).OnClick(func() {
					app.memoryLoad = true
					app.manualMapping = true
					app.peHeaderErasure = true
					app.pathSpoofing = true
					app.pteSpoofing = true
					app.vadManipulation = true
					app.directSyscalls = true
					app.addLogLine("Maximum evasion preset applied")
				}),
				giu.Button("Clear All").Size(120, 30).OnClick(func() {
					app.clearAllOptions()
					app.addLogLine("All options cleared")
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
						app.onInjectClicked()
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
				giu.Button("Home").Size(50, 25).OnClick(func() {
					// Home button functionality can be implemented here if needed
				}),
			),
		),
		giu.Spacing(),
		// Console text area with dark background - use remaining space
		giu.Style().SetColor(giu.StyleColorFrameBg, color.RGBA{R: 25, G: 25, B: 25, A: 255}).To(
			giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 180, G: 180, B: 180, A: 255}).To(
				giu.InputTextMultiline(&logText).Size(-1, -1).Flags(giu.InputTextFlagsReadOnly),
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

// buildProcessSelectionDialog builds the process selection dialog
func (app *Application) buildProcessSelectionDialog() {
	if !app.showProcessDialog {
		return
	}

	giu.Window("Select Target Process").
		IsOpen(&app.showProcessDialog).
		Size(900, 500).
		Flags(giu.WindowFlagsNoResize | giu.WindowFlagsNoCollapse).
		Layout(
			giu.Column(
				// Header
				giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 0, G: 122, B: 204, A: 255}).To(
					giu.Label("Select Target Process for DLL Injection"),
				),
				giu.Separator(),
				giu.Spacing(),

				// Search section
				giu.Row(
					giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 170, G: 170, B: 170, A: 255}).To(
						giu.Label("Search:"),
					),
					giu.InputText(&app.processSearchText).Hint("Type process name, PID, or path...").Size(400),
					giu.Button("Refresh List").OnClick(func() {
						app.refreshProcessList()
						app.addLogLine("Process list refreshed")
					}),
				),
				giu.Spacing(),

				// Process list header
				giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 200, G: 200, B: 200, A: 255}).To(
					giu.Row(
						giu.Label("PID"),
						giu.Dummy(80, 0),
						giu.Label("Process Name"),
						giu.Dummy(150, 0),
						giu.Label("Executable Path"),
						giu.Dummy(300, 0),
						giu.Label("Action"),
					),
				),
				giu.Separator(),

				// Scrollable process list
				giu.Child().Size(-1, 300).Layout(
					app.buildProcessListContent(),
				),

				giu.Spacing(),
				// Bottom buttons
				giu.Row(
					giu.Style().SetColor(giu.StyleColorButton, color.RGBA{R: 80, G: 80, B: 80, A: 255}).To(
						giu.Button("Cancel").Size(100, 30).OnClick(func() {
							app.showProcessDialog = false
							app.processSearchText = ""
							app.addLogLine("Process selection cancelled")
						}),
					),
				),
			),
		)
}

// buildProcessListContent builds the scrollable process list content
func (app *Application) buildProcessListContent() giu.Widget {
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

	// Limit processes for performance
	maxProcesses := 50
	if len(filteredProcesses) > maxProcesses {
		filteredProcesses = filteredProcesses[:maxProcesses]
	}

	var processWidgets []giu.Widget

	// Add process rows
	for _, proc := range filteredProcesses {
		proc := proc // Capture for closure

		// Truncate long paths
		execPath := proc.Executable
		if len(execPath) > 50 {
			execPath = "..." + execPath[len(execPath)-47:]
		}

		isSelected := proc.PID == app.selectedPID

		// Create clickable row using Selectable
		processText := fmt.Sprintf("%-8d %-20s %s", proc.PID, proc.Name, execPath)

		var rowWidget giu.Widget
		if isSelected {
			// Highlight selected process with green background
			rowWidget = giu.Style().
				SetColor(giu.StyleColorText, color.RGBA{R: 255, G: 255, B: 255, A: 255}).
				SetColor(giu.StyleColorHeader, color.RGBA{R: 0, G: 100, B: 0, A: 100}).
				SetColor(giu.StyleColorHeaderHovered, color.RGBA{R: 0, G: 120, B: 0, A: 120}).
				SetColor(giu.StyleColorHeaderActive, color.RGBA{R: 0, G: 140, B: 0, A: 140}).To(
				giu.Selectable(processText).Selected(true).OnClick(func() {
					app.selectedPID = proc.PID
					app.selectedProcessName = proc.Name
					app.showProcessDialog = false
					app.processSearchText = ""
					app.addLogLine(fmt.Sprintf("✅ Process selected: %s (PID: %d)", proc.Name, proc.PID))
				}),
			)
		} else {
			// Normal process row - clickable
			rowWidget = giu.Style().
				SetColor(giu.StyleColorText, color.RGBA{R: 200, G: 200, B: 200, A: 255}).
				SetColor(giu.StyleColorHeader, color.RGBA{R: 40, G: 40, B: 40, A: 100}).
				SetColor(giu.StyleColorHeaderHovered, color.RGBA{R: 60, G: 60, B: 60, A: 120}).
				SetColor(giu.StyleColorHeaderActive, color.RGBA{R: 80, G: 80, B: 80, A: 140}).To(
				giu.Selectable(processText).Selected(false).OnClick(func() {
					app.selectedPID = proc.PID
					app.selectedProcessName = proc.Name
					app.showProcessDialog = false
					app.processSearchText = ""
					app.addLogLine(fmt.Sprintf("✅ Process selected: %s (PID: %d)", proc.Name, proc.PID))
				}),
			)
		}

		processWidgets = append(processWidgets, rowWidget)
	}

	// Add info footer
	processWidgets = append(processWidgets,
		giu.Spacing(),
		giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 150, G: 150, B: 150, A: 255}).To(
			giu.Label(fmt.Sprintf("Showing %d of %d processes", len(filteredProcesses), len(processes))),
		),
	)

	return giu.Column(processWidgets...)
}

// Legacy file dialog functions removed - now using Windows native dialog

// Legacy file dialog helper functions removed - now using Windows native dialog

// openNativeFileDialog opens Windows native file dialog for DLL selection
func (app *Application) openNativeFileDialog() {
	// Use Windows GetOpenFileName API
	filename, err := app.showWindowsFileDialog()
	if err != nil {
		app.addLogLine(fmt.Sprintf("Error opening file dialog: %v", err))
		return
	}

	if filename != "" {
		app.selectedDllPath = filename
		app.addLogLine(fmt.Sprintf("DLL file selected: %s", filepath.Base(filename)))
	} else {
		app.addLogLine("File selection cancelled")
	}
}

// showWindowsFileDialog shows Windows native file dialog
func (app *Application) showWindowsFileDialog() (string, error) {
	// Load comdlg32.dll
	comdlg32 := windows.NewLazyDLL("comdlg32.dll")
	getOpenFileName := comdlg32.NewProc("GetOpenFileNameW")

	// Prepare OPENFILENAME structure
	var ofn struct {
		lStructSize       uint32
		hwndOwner         uintptr
		hInstance         uintptr
		lpstrFilter       *uint16
		lpstrCustomFilter *uint16
		nMaxCustFilter    uint32
		nFilterIndex      uint32
		lpstrFile         *uint16
		nMaxFile          uint32
		lpstrFileTitle    *uint16
		nMaxFileTitle     uint32
		lpstrInitialDir   *uint16
		lpstrTitle        *uint16
		flags             uint32
		nFileOffset       uint16
		nFileExtension    uint16
		lpstrDefExt       *uint16
		lCustData         uintptr
		lpfnHook          uintptr
		lpTemplateName    *uint16
		pvReserved        uintptr
		dwReserved        uint32
		flagsEx           uint32
	}

	// Prepare filter string: "DLL Files\0*.dll\0All Files\0*.*\0\0"
	filter := "DLL Files\x00*.dll\x00All Files\x00*.*\x00\x00"
	filterPtr, _ := syscall.UTF16PtrFromString(filter)

	// Prepare title
	title := "Select DLL File for Injection"
	titlePtr, _ := syscall.UTF16PtrFromString(title)

	// Prepare file buffer
	fileBuffer := make([]uint16, 260) // MAX_PATH

	// Fill OPENFILENAME structure
	ofn.lStructSize = uint32(unsafe.Sizeof(ofn))
	ofn.lpstrFilter = filterPtr
	ofn.lpstrFile = &fileBuffer[0]
	ofn.nMaxFile = uint32(len(fileBuffer))
	ofn.lpstrTitle = titlePtr
	ofn.flags = 0x00080000 | 0x00001000 | 0x00000800 // OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST

	// Call GetOpenFileName
	ret, _, _ := getOpenFileName.Call(uintptr(unsafe.Pointer(&ofn)))

	if ret == 0 {
		// User cancelled or error occurred
		return "", nil
	}

	// Convert result to string
	filename := syscall.UTF16ToString(fileBuffer)
	return filename, nil
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
						giu.Button("Selected").OnClick(func() {
							app.selectedPID = proc.PID
							app.selectedProcessName = proc.Name
							app.showProcessDialog = false
							app.processSearchText = "" // Clear search
							app.addLogLine(fmt.Sprintf("Process selected: %s (PID: %d)", proc.Name, proc.PID))
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
						app.addLogLine(fmt.Sprintf("Process selected: %s (PID: %d)", proc.Name, proc.PID))
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
				app.buildCompatibleCheckbox("Memory Load", "memory_load", &app.memoryLoad),
				app.buildCompatibleCheckbox("Manual Mapping", "manual_mapping", &app.manualMapping),
			),
			giu.Row(
				app.buildCompatibleCheckbox("Path Spoofing", "path_spoofing", &app.pathSpoofing),
				app.buildCompatibleCheckbox("PE Header Erasure", "pe_header_erasure", &app.peHeaderErasure),
			),
			giu.Row(
				app.buildCompatibleCheckbox("Entry Point Erase", "entry_point_erasure", &app.entryPointErase),
				app.buildCompatibleCheckbox("Invisible Memory", "invisible_memory", &app.invisibleMemory),
			),

			giu.Spacing(),

			// Advanced Options
			giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 255, G: 255, B: 51, A: 255}).To(
				giu.Label("Advanced Options:"),
			),
			giu.Row(
				app.buildCompatibleCheckbox("PTE Spoofing", "pte_spoofing", &app.pteSpoofing),
				app.buildCompatibleCheckbox("VAD Manipulation", "vad_manipulation", &app.vadManipulation),
			),
			giu.Row(
				app.buildCompatibleCheckbox("Remove VAD Node", "remove_vad_node", &app.removeVADNode),
				app.buildCompatibleCheckbox("Thread Stack Alloc", "thread_stack_allocation", &app.allocBehindThreadStack),
			),
			giu.Row(
				app.buildCompatibleCheckbox("Direct Syscalls", "direct_syscalls", &app.directSyscalls),
				app.buildCompatibleCheckbox("Legit Process", "legit_process", &app.legitProcessInjection),
			),

			giu.Spacing(),

			// Enhanced Options
			giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 255, G: 255, B: 51, A: 255}).To(
				giu.Label("Enhanced Options:"),
			),
			giu.Row(
				app.buildCompatibleCheckbox("Randomize Allocation", "randomize_allocation", &app.randomizeAllocation),
				app.buildCompatibleCheckbox("Delayed Execution", "delayed_execution", &app.delayedExecution),
			),
			giu.Row(
				app.buildCompatibleCheckbox("Multi-Stage Injection", "multi_stage_injection", &app.multiStageInjection),
				app.buildCompatibleCheckbox("Anti-Debug", "anti_debug", &app.antiDebugTechniques),
			),
			giu.Row(
				app.buildCompatibleCheckbox("Process Hollowing", "process_hollowing", &app.processHollowing),
				app.buildCompatibleCheckbox("Thread Hijacking", "thread_hijacking", &app.threadHijacking),
			),
			giu.Row(
				app.buildCompatibleCheckbox("Memory Fluctuation", "memory_fluctuation", &app.memoryFluctuation),
				app.buildCompatibleCheckbox("Anti-VM", "anti_vm", &app.antiVMTechniques),
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
		app.addLogLine("❌ Error: No DLL file selected")
		app.logger.Error("No DLL file selected")
		return
	}

	if app.selectedPID <= 0 {
		app.addLogLine("❌ Error: No target process selected")
		app.logger.Error("No target process selected")
		return
	}

	// Validate DLL file exists
	if _, err := os.Stat(app.selectedDllPath); os.IsNotExist(err) {
		app.addLogLine(fmt.Sprintf("❌ Error: DLL file does not exist: %s", app.selectedDllPath))
		app.logger.Error("DLL file does not exist", zap.String("path", app.selectedDllPath))
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
	app.performInjection()
}

// performInjection performs the actual DLL injection
func (app *Application) performInjection() {
	app.logger.Info("=== Starting performInjection ===")

	// 详细记录当前状态
	app.logger.Info("GUI Injection Parameters:",
		zap.String("dll_path", app.selectedDllPath),
		zap.Int32("process_id", app.selectedPID),
		zap.String("process_name", app.selectedProcessName),
		zap.Int32("injection_method", app.injectionMethod),
	)

	app.progressText = "Preparing injection..."
	app.showProgressDialog = true
	app.logger.Info("Progress dialog should be shown")

	go func() {
		app.logger.Info("=== Injection goroutine started ===")

		// 验证参数
		if app.selectedDllPath == "" {
			app.logger.Error("DLL path is empty in GUI")
			result := InjectionResult{
				Success: false,
				Error:   fmt.Errorf("DLL path is empty"),
				Message: "",
			}
			app.injectionResultChan <- result
			return
		}

		if app.selectedPID <= 0 {
			app.logger.Error("Invalid process ID in GUI", zap.Int32("pid", app.selectedPID))
			result := InjectionResult{
				Success: false,
				Error:   fmt.Errorf("invalid process ID: %d", app.selectedPID),
				Message: "",
			}
			app.injectionResultChan <- result
			return
		}

		app.logger.Info("Creating injector instance")
		loggerAdapter := &LoggerAdapter{logger: app.logger}
		inj := injector.NewInjector(app.selectedDllPath, uint32(app.selectedPID), loggerAdapter)

		if inj == nil {
			app.logger.Error("Failed to create injector instance")
			result := InjectionResult{
				Success: false,
				Error:   fmt.Errorf("failed to create injector instance"),
				Message: "",
			}
			app.injectionResultChan <- result
			return
		}

		// Set injection method
		app.logger.Info("Setting injection method", zap.Int32("method", app.injectionMethod))
		inj.SetMethod(injector.InjectionMethod(app.injectionMethod))

		// Set basic anti-detection options (simplified to avoid conflicts)
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

		app.logger.Info("Setting bypass options",
			zap.Bool("memory_load", options.MemoryLoad),
			zap.Bool("manual_mapping", options.ManualMapping),
		)
		inj.SetBypassOptions(options)

		// Perform injection
		app.logger.Info("=== CALLING ACTUAL INJECTION ===")
		// Use thread-safe logging from background goroutine
		app.addLogLine("🔄 Starting injection process...")

		// 确保这里实际调用了注入
		err := inj.Inject()

		app.logger.Info("=== INJECTION CALL COMPLETED ===",
			zap.Bool("success", err == nil),
			zap.Error(err),
		)

		// Prepare result message
		var resultMsg string
		if err == nil {
			resultMsg = fmt.Sprintf(
				"DLL: %s\nProcess: %s (PID: %d)\nMethod: %s",
				filepath.Base(app.selectedDllPath),
				app.selectedProcessName,
				app.selectedPID,
				app.methodNames[app.injectionMethod],
			)
		}

		// Send result to main thread via channel
		result := InjectionResult{
			Success: err == nil,
			Error:   err,
			Message: resultMsg,
		}

		app.logger.Info("Sending injection result to main thread",
			zap.Bool("success", result.Success),
			zap.String("error_msg", func() string {
				if result.Error != nil {
					return result.Error.Error()
				}
				return "none"
			}()),
		)

		// Enhanced channel communication with retry mechanism
		sent := false
		for attempts := 0; attempts < 3 && !sent; attempts++ {
			select {
			case app.injectionResultChan <- result:
				app.logger.Info("Injection result sent successfully")
				sent = true
			case <-time.After(2 * time.Second):
				app.logger.Warn("Injection result send timeout", zap.Int("attempt", attempts+1))
				if attempts == 2 {
					app.logger.Error("Failed to send injection result after 3 attempts")
					// Force add error message directly to ensure user sees it
					go func() {
						time.Sleep(100 * time.Millisecond)
						app.addLogLine("❌ Error: Failed to communicate injection result")
					}()
				}
			}
		}

		app.logger.Info("=== Injection goroutine finished ===")
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
