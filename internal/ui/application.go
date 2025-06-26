package ui

import (
	"fmt"
	"image/color"
	"strconv"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	fyneapp "fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/whispin/dll-injector/internal/injector"
	"github.com/whispin/dll-injector/internal/process"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// LoggerAdapter adapts zap.Logger to injector.Logger interface
type LoggerAdapter struct {
	logger *zap.Logger
}

// NewLoggerAdapter creates a new adapter for zap.Logger
func NewLoggerAdapter(logger *zap.Logger) *LoggerAdapter {
	return &LoggerAdapter{logger: logger}
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
	if len(fields)%2 != 0 {
		// If there's an odd number of fields, add an empty string to complete the pair
		fields = append(fields, "")
	}

	zapFields := make([]zap.Field, 0, len(fields)/2)
	for i := 0; i < len(fields); i += 2 {
		key, ok := fields[i].(string)
		if !ok {
			key = fmt.Sprintf("%v", fields[i])
		}

		value := fields[i+1]
		switch v := value.(type) {
		case string:
			zapFields = append(zapFields, zap.String(key, v))
		case int:
			zapFields = append(zapFields, zap.Int(key, v))
		case int32:
			zapFields = append(zapFields, zap.Int32(key, v))
		case int64:
			zapFields = append(zapFields, zap.Int64(key, v))
		case uint:
			zapFields = append(zapFields, zap.Uint(key, v))
		case uint32:
			zapFields = append(zapFields, zap.Uint32(key, v))
		case uint64:
			zapFields = append(zapFields, zap.Uint64(key, v))
		case float32:
			zapFields = append(zapFields, zap.Float32(key, v))
		case float64:
			zapFields = append(zapFields, zap.Float64(key, v))
		case bool:
			zapFields = append(zapFields, zap.Bool(key, v))
		case error:
			zapFields = append(zapFields, zap.Error(v))
		default:
			zapFields = append(zapFields, zap.Any(key, v))
		}
	}
	return zapFields
}

// consoleLog is a custom zap core for storing console logs
type consoleLog struct {
	binding binding.StringList
	mu      sync.Mutex
	maxSize int
}

// addLogEntry 添加一条日志条目，处理日志轮换
func (c *consoleLog) addLogEntry(text string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 添加日志条目
	length := c.binding.Length()

	// 如果超出最大行数，移除最早的日志
	if length >= c.maxSize {
		// 克隆当前日志，排除第一项
		texts := make([]string, 0, length-1)
		for i := 1; i < length; i++ {
			item, _ := c.binding.GetValue(i)
			texts = append(texts, item)
		}
		// 添加新日志
		texts = append(texts, text)
		c.binding.Set(texts)
	} else {
		// 直接添加到末尾
		c.binding.Append(text)
	}
}

// Write implements io.Writer interface for log output
func (c *consoleLog) Write(p []byte) (n int, err error) {
	// 直接使用UTF-8解码字节
	text := string(p)
	text = strings.TrimRight(text, "\r\n")

	if text == "" {
		return len(p), nil
	}

	// 添加短时间戳
	timestamp := time.Now().Format("15:04")
	text = fmt.Sprintf("%s %s", timestamp, text)

	// 使用通用方法添加日志
	c.addLogEntry(text)

	return len(p), nil
}

// WriteLog 为zapcore实现的日志写入
func (c *consoleLog) WriteLog(enc zapcore.Encoder, entry zapcore.Entry, fields []zapcore.Field) error {
	// 直接使用纯文本格式，避免特殊字符
	var sb strings.Builder

	// 添加时间
	sb.WriteString(time.Now().Format("15:04"))
	sb.WriteString(" ")

	// 添加日志级别
	switch entry.Level {
	case zapcore.InfoLevel:
		sb.WriteString("INFO")
	case zapcore.WarnLevel:
		sb.WriteString("WARN")
	case zapcore.ErrorLevel:
		sb.WriteString("ERROR")
	case zapcore.DebugLevel:
		sb.WriteString("DEBUG")
	default:
		sb.WriteString(entry.Level.String())
	}
	sb.WriteString(" ")

	// 添加消息 - 确保直接写入，不做额外处理
	sb.WriteString(entry.Message)

	// 添加字段
	if len(fields) > 0 {
		sb.WriteString(" ")
		for i, field := range fields {
			if i > 0 {
				sb.WriteString(", ")
			}
			// 简化字段显示
			sb.WriteString(field.Key)
			sb.WriteString(": ")

			// 根据字段类型格式化值，确保字符串类型直接原样写入
			switch field.Type {
			case zapcore.StringType:
				sb.WriteString(field.String)
			case zapcore.Int64Type, zapcore.Int32Type, zapcore.Int16Type, zapcore.Int8Type:
				sb.WriteString(strconv.FormatInt(field.Integer, 10))
			case zapcore.Uint64Type, zapcore.Uint32Type, zapcore.Uint16Type, zapcore.Uint8Type:
				sb.WriteString(strconv.FormatUint(uint64(field.Integer), 10))
			case zapcore.BoolType:
				sb.WriteString(strconv.FormatBool(field.Integer == 1))
			default:
				// 直接写入界面的值，避免格式化导致的编码问题
				if s, ok := field.Interface.(string); ok {
					sb.WriteString(s)
				} else {
					sb.WriteString(fmt.Sprintf("%v", field.Interface))
				}
			}
		}
	}

	// 获取日志文本
	text := sb.String()

	// 使用通用方法添加日志
	c.addLogEntry(text)

	return nil
}

// Sync 实现zapcore.Core接口所需的Sync方法
func (c *consoleLog) Sync() error {
	return nil
}

// zapConsoleCore 实现了zapcore.Core接口，将日志写入控制台
type zapConsoleCore struct {
	encoder zapcore.Encoder
	console *consoleLog
	level   zapcore.LevelEnabler
}

// newZapConsoleCore 创建一个新的zapConsoleCore
func newZapConsoleCore(enc zapcore.Encoder, console *consoleLog, level zapcore.LevelEnabler) zapcore.Core {
	return &zapConsoleCore{
		encoder: enc,
		console: console,
		level:   level,
	}
}

// Enabled 实现zapcore.Core接口
func (c *zapConsoleCore) Enabled(lvl zapcore.Level) bool {
	return c.level.Enabled(lvl)
}

// With 实现zapcore.Core接口
func (c *zapConsoleCore) With(fields []zapcore.Field) zapcore.Core {
	clone := c.clone()
	for i := range fields {
		fields[i].AddTo(clone.encoder)
	}
	return clone
}

// Check 实现zapcore.Core接口
func (c *zapConsoleCore) Check(ent zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(ent.Level) {
		return ce.AddCore(ent, c)
	}
	return ce
}

// Write 实现zapcore.Core接口
func (c *zapConsoleCore) Write(ent zapcore.Entry, fields []zapcore.Field) error {
	return c.console.WriteLog(c.encoder, ent, fields)
}

// Sync 实现zapcore.Core接口
func (c *zapConsoleCore) Sync() error {
	return nil
}

// clone 克隆当前Core
func (c *zapConsoleCore) clone() *zapConsoleCore {
	return &zapConsoleCore{
		encoder: c.encoder.Clone(),
		console: c.console,
		level:   c.level,
	}
}

// Application 表示整个GUI应用程序
type Application struct {
	fyneApp      fyne.App
	mainWindow   fyne.Window
	title        string
	width        float32
	height       float32
	processInfo  *process.Info
	processes    []process.ProcessEntry
	selectedDll  binding.String
	selectedPID  int32
	selectedProc string
	processList  *widget.List
	searchEntry  *widget.Entry

	// 控制台日志
	consoleLog      *consoleLog
	consoleView     *ConsoleText      // 改用ConsoleText组件代替Entry
	scrollContainer *container.Scroll // 滚动容器引用
	logger          *zap.Logger

	// 日志绑定监听器
	logListener binding.DataListener

	// 反检测选项
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

	// 增强的高级选项
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

	// 注入方法选择
	injectionMethod int    // 0: 标准注入, 1: SetWindowsHookEx, 2: QueueUserAPC, 3: Early Bird APC, 4: DLL通知, 5: 冷冻进程
	selectedMethod  string // 存储当前选中的注入方法名称

	// 检查框组件引用
	bypassCheckboxes     map[string]*widget.Check
	selectedProcessLabel *widget.Label // 显示选中的进程信息
}

// NewApplication 创建一个新的GUI应用程序实例
func NewApplication(title string, width, height int) *Application {
	app := &Application{
		fyneApp:          fyneapp.New(),
		title:            title,
		width:            float32(width),
		height:           float32(height + 250),
		processInfo:      process.NewInfo(),
		selectedPID:      -1,
		selectedDll:      binding.NewString(),
		bypassCheckboxes: make(map[string]*widget.Check),
		injectionMethod:  0, // Initialize injectionMethod
	}

	// 初始化控制台日志
	app.consoleLog = &consoleLog{
		binding: binding.NewStringList(),
		maxSize: 1000, // 最多保留1000行日志
	}

	// 配置zap logger - 确保正确处理UTF-8编码
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "",  // 不使用时间字段，由我们自己添加
		LevelKey:       "",  // 不使用级别字段，由我们自己添加
		NameKey:        "",  // 不使用名称字段
		CallerKey:      "",  // 不使用调用者字段
		FunctionKey:    "",  // 不使用函数字段
		MessageKey:     "M", // 消息字段
		StacktraceKey:  "",  // 不使用堆栈跟踪字段
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.CapitalLevelEncoder,
		EncodeTime:     zapcore.RFC3339TimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
		EncodeName:     zapcore.FullNameEncoder,
	}

	// 使用控制台编码器，确保正确编码中文
	consoleEncoder := zapcore.NewConsoleEncoder(encoderConfig)

	consoleCore := newZapConsoleCore(
		consoleEncoder,
		app.consoleLog,
		zapcore.InfoLevel,
	)

	app.logger = zap.New(consoleCore)

	// Set the global logger for injector package
	loggerAdapter := NewLoggerAdapter(app.logger)
	injector.SetLogger(loggerAdapter)

	return app
}

// Log 返回应用的logger
func (app *Application) Log() *zap.Logger {
	return app.logger
}

// Run 启动应用程序主循环
func (app *Application) Run() error {
	// 初始化Fyne应用和窗口
	app.fyneApp = fyneapp.New()

	// 应用现代主题
	app.fyneApp.Settings().SetTheme(NewModernTheme())

	app.mainWindow = app.fyneApp.NewWindow(app.title)
	app.mainWindow.Resize(fyne.NewSize(app.width, app.height))

	// 设置窗口图标
	app.mainWindow.SetIcon(theme.ComputerIcon())

	// 初始化进程信息
	app.processInfo = process.NewInfo()
	app.refreshProcessList()

	// 记录启动日志
	app.logger.Info("DLL Injector started")

	// 创建内容
	content := app.createContent()

	// 设置窗口内容
	app.mainWindow.SetContent(content)

	// 运行应用
	app.mainWindow.ShowAndRun()

	return nil
}

// createContent 创建主界面内容
func (app *Application) createContent() fyne.CanvasObject {
	// 创建左侧面板
	leftPanel := app.createLeftPanel()

	// 创建控制台日志区域
	consolePanel := app.createConsolePanel()

	// 创建垂直分割，上面是主界面，下面是控制台
	mainContainer := container.NewVSplit(
		leftPanel,
		consolePanel,
	)
	mainContainer.SetOffset(0.8) // 控制台占20%高度

	return mainContainer
}

// createConsolePanel 创建控制台日志面板
func (app *Application) createConsolePanel() fyne.CanvasObject {
	// Create a console panel with a title
	consoleTitle := widget.NewLabelWithStyle("Console Logs", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	// Title bar - buttons removed
	titleBar := container.NewBorder(
		nil, nil,
		consoleTitle,
		nil, // Button area removed
	)

	// Create console text view - VS Code dark theme colors
	app.consoleView = NewConsoleText(
		color.RGBA{R: 25, G: 25, B: 25, A: 255},    // VS Code darker background
		color.RGBA{R: 204, G: 204, B: 204, A: 255}, // VS Code primary text
	)

	// Create a scroll container for logs
	scrollContainer := container.NewScroll(app.consoleView)
	scrollContainer.SetMinSize(fyne.NewSize(800, 200)) // Set minimum size

	// Store scroll container reference for auto-scrolling
	app.scrollContainer = scrollContainer

	// Set log binding listener, update UI when logs are updated
	app.logListener = binding.NewDataListener(func() {
		// Update log text area first
		app.updateLogTextArea()

		// Auto-scroll to bottom with multiple attempts to ensure reliability
		go func() {
			// Multiple scroll attempts with increasing delays
			for i := 0; i < 3; i++ {
				time.Sleep(time.Duration(20*(i+1)) * time.Millisecond)
				fyne.Do(func() {
					if app.scrollContainer != nil {
						app.scrollContainer.ScrollToBottom()
					}
				})
			}
		}()
	})
	app.consoleLog.binding.AddListener(app.logListener)

	// Initially display existing logs
	app.updateLogTextArea()

	// Assemble console panel
	consolePanel := container.NewBorder(
		titleBar,
		nil, nil, nil,
		scrollContainer, // Use scrollable console view
	)

	return consolePanel
}

// createLeftPanel 创建左侧面板，包含DLL选择和注入设置
func (app *Application) createLeftPanel() fyne.CanvasObject {
	// DLL selection with inline label design
	dllEntry := widget.NewEntryWithData(app.selectedDll)
	dllEntry.SetPlaceHolder("Select DLL file path...")
	dllEntry.Wrapping = fyne.TextTruncate
	// Set a reasonable maximum width for the entry
	dllEntry.Resize(fyne.NewSize(200, dllEntry.MinSize().Height))

	browseDllButton := CompactIconButton("", theme.FolderOpenIcon(), func() {
		fd := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil {
				app.logger.Error("File selection error", zap.Error(err))
				return
			}
			if reader == nil {
				return
			}
			path := reader.URI().Path()
			app.selectedDll.Set(path)
			app.logger.Info("DLL file selected", zap.String("path", path))
		}, app.mainWindow)

		// Set to only show DLL files
		fd.SetFilter(&dllFilter{})
		fd.Show()
	})

	// Create compact DLL selector with inline label using the new component
	dllSelector := InlineLabelEntry("DLL File:", dllEntry, browseDllButton)

	// Create a simple card for the DLL selector
	dllCard := NewCard(dllSelector, false)

	// Injection method selection - using radio button group, more obvious
	injectMethods := []string{
		"Standard Injection",
		"SetWindowsHookEx",
		"QueueUserAPC",
		"Early Bird",
		"DLL Notification",
		"Job Object",
	}

	// Create radio button group
	methodRadioGroup := widget.NewRadioGroup(injectMethods, nil)
	// Set to horizontal
	methodRadioGroup.Horizontal = true

	// Set callback function
	methodRadioGroup.OnChanged = func(selected string) {
		app.selectedMethod = selected
		switch selected {
		case "Standard Injection":
			app.injectionMethod = int(injector.StandardInjection)
			app.logger.Info("Injection method selected", zap.String("method", "Standard Injection"))
		case "SetWindowsHookEx":
			app.injectionMethod = int(injector.SetWindowsHookExInjection)
			app.logger.Info("Injection method selected", zap.String("method", "SetWindowsHookEx Injection"))
		case "QueueUserAPC":
			app.injectionMethod = int(injector.QueueUserAPCInjection)
			app.logger.Info("Injection method selected", zap.String("method", "QueueUserAPC Injection"))
		case "Early Bird":
			app.injectionMethod = int(injector.EarlyBirdAPCInjection)
			app.logger.Info("Injection method selected", zap.String("method", "Early Bird APC Injection"))
		case "DLL Notification":
			app.injectionMethod = int(injector.DllNotificationInjection)
			app.logger.Info("Injection method selected", zap.String("method", "DLL Notification Injection"))
		case "Job Object":
			app.injectionMethod = int(injector.CryoBirdInjection)
			app.logger.Info("Injection method selected", zap.String("method", "Job Object Cold Injection"))
		}

		// Only call updateBypassOptionsState when all options are initialized
		if app.bypassCheckboxes != nil && len(app.bypassCheckboxes) > 0 {
			app.updateBypassOptionsState()
		}
	}

	// Set initial selected item
	if app.injectionMethod >= 0 && app.injectionMethod < len(injectMethods) {
		app.selectedMethod = injectMethods[app.injectionMethod]
	} else {
		app.selectedMethod = injectMethods[0]
		app.injectionMethod = 0
	}
	methodRadioGroup.SetSelected(app.selectedMethod)

	// Create compact injection method selector with inline label
	methodSelector := InlineLabelRadioGroup("Injection Method:", methodRadioGroup)

	// Create a simple card for the method selector
	methodCard := NewCard(methodSelector, false)

	// Anti-detection options - use collapsible panel design
	bypassIcon := widget.NewIcon(theme.WarningIcon())
	bypassTitleLabel := widget.NewLabelWithStyle("Anti-Detection Options", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	bypassTitleContainer := container.NewHBox(
		bypassIcon,
		bypassTitleLabel,
	)

	// Create anti-detection options groups
	// Loading method group

	// Basic anti-detection options
	app.bypassCheckboxes["Load DLL from Memory"] = widget.NewCheck("Load DLL from Memory", func(checked bool) {
		app.memoryLoad = checked
		app.logger.Info("Anti-detection option changed", zap.String("option", "Load DLL from Memory"), zap.Bool("enabled", checked))
		app.updateBypassOptionsState()
	})

	app.bypassCheckboxes["Use Manual Mapping"] = widget.NewCheck("Use Manual Mapping", func(checked bool) {
		app.manualMapping = checked
		app.logger.Info("Anti-detection option changed", zap.String("option", "Use Manual Mapping"), zap.Bool("enabled", checked))

		if checked {
			app.memoryLoad = true
			app.bypassCheckboxes["Load DLL from Memory"].SetChecked(true)
		}

		app.updateBypassOptionsState()
	})

	app.bypassCheckboxes["Path Spoofing"] = widget.NewCheck("Path Spoofing", func(checked bool) {
		app.pathSpoofing = checked
		app.logger.Info("Anti-detection option changed", zap.String("option", "Path Spoofing"), zap.Bool("enabled", checked))
	})

	// Use horizontal layout for options with compact spacing
	loadingOptions := container.NewGridWithColumns(3,
		app.bypassCheckboxes["Load DLL from Memory"],
		app.bypassCheckboxes["Use Manual Mapping"],
		app.bypassCheckboxes["Path Spoofing"],
	)

	loadingCard := ModernSection("Loading Method", loadingOptions)

	// Memory operation group

	// Memory operation options
	app.bypassCheckboxes["Erase PE Header"] = widget.NewCheck("Erase PE Header", func(checked bool) {
		app.peHeaderErasure = checked
		app.logger.Info("Anti-detection option changed", zap.String("option", "Erase PE Header"), zap.Bool("enabled", checked))
	})

	app.bypassCheckboxes["Erase Entry Point"] = widget.NewCheck("Erase Entry Point", func(checked bool) {
		app.entryPointErase = checked
		app.logger.Info("Anti-detection option changed", zap.String("option", "Erase Entry Point"), zap.Bool("enabled", checked))
	})

	app.bypassCheckboxes["Map to Hidden Memory"] = widget.NewCheck("Map to Hidden Memory", func(checked bool) {
		app.invisibleMemory = checked
		app.logger.Info("Anti-detection option changed", zap.String("option", "Map to Hidden Memory"), zap.Bool("enabled", checked))
	})

	// Use horizontal layout for options
	memoryOptions := container.NewGridWithColumns(3,
		app.bypassCheckboxes["Erase PE Header"],
		app.bypassCheckboxes["Erase Entry Point"],
		app.bypassCheckboxes["Map to Hidden Memory"],
	)

	memoryCard := ModernSection("Memory Operations", memoryOptions)

	// Advanced techniques group

	// Advanced anti-detection options
	app.bypassCheckboxes["PTE Modification"] = widget.NewCheck("PTE Modification", func(checked bool) {
		app.pteSpoofing = checked
		app.logger.Info("Anti-detection option changed", zap.String("option", "PTE Modification"), zap.Bool("enabled", checked))

		if checked && app.vadManipulation {
			app.vadManipulation = false
			app.bypassCheckboxes["VAD Manipulation"].SetChecked(false)
		}
	})

	app.bypassCheckboxes["VAD Manipulation"] = widget.NewCheck("VAD Manipulation", func(checked bool) {
		app.vadManipulation = checked
		app.logger.Info("Anti-detection option changed", zap.String("option", "VAD Manipulation"), zap.Bool("enabled", checked))

		if checked && app.pteSpoofing {
			app.pteSpoofing = false
			app.bypassCheckboxes["PTE Modification"].SetChecked(false)
		}
	})

	app.bypassCheckboxes["Remove VAD Node"] = widget.NewCheck("Remove VAD Node", func(checked bool) {
		app.removeVADNode = checked
		app.logger.Info("Anti-detection option changed", zap.String("option", "Remove VAD Node"), zap.Bool("enabled", checked))

		if checked && !app.vadManipulation {
			app.vadManipulation = true
			app.bypassCheckboxes["VAD Manipulation"].SetChecked(true)

			if app.vadManipulation && app.pteSpoofing {
				app.pteSpoofing = false
				app.bypassCheckboxes["PTE Modification"].SetChecked(false)
			}
		}
	})

	app.bypassCheckboxes["Allocate Behind Thread Stack"] = widget.NewCheck("Allocate Behind Thread Stack", func(checked bool) {
		app.allocBehindThreadStack = checked
		app.logger.Info("Anti-detection option changed", zap.String("option", "Allocate Behind Thread Stack"), zap.Bool("enabled", checked))
	})

	app.bypassCheckboxes["Direct Syscalls"] = widget.NewCheck("Direct Syscalls", func(checked bool) {
		app.directSyscalls = checked
		app.logger.Info("Anti-detection option changed", zap.String("option", "Direct Syscalls"), zap.Bool("enabled", checked))
	})

	app.bypassCheckboxes["Use Legitimate Process"] = widget.NewCheck("Use Legitimate Process", func(checked bool) {
		app.legitProcessInjection = checked
		app.logger.Info("Anti-detection option changed", zap.String("option", "Use Legitimate Process"), zap.Bool("enabled", checked))
	})

	// First row of advanced options
	advancedOptions1 := container.NewGridWithColumns(3,
		app.bypassCheckboxes["PTE Modification"],
		app.bypassCheckboxes["VAD Manipulation"],
		app.bypassCheckboxes["Remove VAD Node"],
	)

	// Second row of advanced options
	advancedOptions2 := container.NewGridWithColumns(3,
		app.bypassCheckboxes["Allocate Behind Thread Stack"],
		app.bypassCheckboxes["Direct Syscalls"],
		app.bypassCheckboxes["Use Legitimate Process"],
	)

	// Enhanced advanced options title

	// Memory options
	app.bypassCheckboxes["Randomize Allocation"] = widget.NewCheck("Randomize Allocation", func(checked bool) {
		app.randomizeAllocation = checked
		app.logger.Info("Enhanced option changed", zap.String("option", "Randomize Allocation"), zap.Bool("enabled", checked))
	})

	app.bypassCheckboxes["Memory Fluctuation"] = widget.NewCheck("Memory Fluctuation", func(checked bool) {
		app.memoryFluctuation = checked
		app.logger.Info("Enhanced option changed", zap.String("option", "Memory Fluctuation"), zap.Bool("enabled", checked))
	})

	app.bypassCheckboxes["Multi-Stage Injection"] = widget.NewCheck("Multi-Stage Injection", func(checked bool) {
		app.multiStageInjection = checked
		app.logger.Info("Enhanced option changed", zap.String("option", "Multi-Stage Injection"), zap.Bool("enabled", checked))
	})

	// First row of enhanced memory options
	enhancedMemoryOptions := container.NewGridWithColumns(3,
		app.bypassCheckboxes["Randomize Allocation"],
		app.bypassCheckboxes["Memory Fluctuation"],
		app.bypassCheckboxes["Multi-Stage Injection"],
	)

	// Thread options
	app.bypassCheckboxes["Thread Hijacking"] = widget.NewCheck("Thread Hijacking", func(checked bool) {
		app.threadHijacking = checked
		app.logger.Info("Enhanced option changed", zap.String("option", "Thread Hijacking"), zap.Bool("enabled", checked))

		// Thread hijacking and stealthy threads are mutually exclusive
		if checked && app.stealthyThreads {
			app.stealthyThreads = false
			app.bypassCheckboxes["Stealthy Threads"].SetChecked(false)
		}
	})

	app.bypassCheckboxes["APC Queueing"] = widget.NewCheck("APC Queueing", func(checked bool) {
		app.apcQueueing = checked
		app.logger.Info("Enhanced option changed", zap.String("option", "APC Queueing"), zap.Bool("enabled", checked))
	})

	app.bypassCheckboxes["Stealthy Threads"] = widget.NewCheck("Stealthy Threads", func(checked bool) {
		app.stealthyThreads = checked
		app.logger.Info("Enhanced option changed", zap.String("option", "Stealthy Threads"), zap.Bool("enabled", checked))

		// Thread hijacking and stealthy threads are mutually exclusive
		if checked && app.threadHijacking {
			app.threadHijacking = false
			app.bypassCheckboxes["Thread Hijacking"].SetChecked(false)
		}
	})

	// Thread options row
	enhancedThreadOptions := container.NewGridWithColumns(3,
		app.bypassCheckboxes["Thread Hijacking"],
		app.bypassCheckboxes["APC Queueing"],
		app.bypassCheckboxes["Stealthy Threads"],
	)

	// Process options
	app.bypassCheckboxes["Process Hollowing"] = widget.NewCheck("Process Hollowing", func(checked bool) {
		app.processHollowing = checked
		app.logger.Info("Enhanced option changed", zap.String("option", "Process Hollowing"), zap.Bool("enabled", checked))

		// Process hollowing and doppelganging are mutually exclusive
		if checked && app.doppelgangingProcess {
			app.doppelgangingProcess = false
			app.bypassCheckboxes["Process Doppelganging"].SetChecked(false)
		}
	})

	app.bypassCheckboxes["Process Doppelganging"] = widget.NewCheck("Process Doppelganging", func(checked bool) {
		app.doppelgangingProcess = checked
		app.logger.Info("Enhanced option changed", zap.String("option", "Process Doppelganging"), zap.Bool("enabled", checked))

		// Process hollowing and doppelganging are mutually exclusive
		if checked && app.processHollowing {
			app.processHollowing = false
			app.bypassCheckboxes["Process Hollowing"].SetChecked(false)
		}
	})

	app.bypassCheckboxes["Process Mirroring"] = widget.NewCheck("Process Mirroring", func(checked bool) {
		app.processMirroring = checked
		app.logger.Info("Enhanced option changed", zap.String("option", "Process Mirroring"), zap.Bool("enabled", checked))
	})

	// Process options row
	enhancedProcessOptions := container.NewGridWithColumns(3,
		app.bypassCheckboxes["Process Hollowing"],
		app.bypassCheckboxes["Process Doppelganging"],
		app.bypassCheckboxes["Process Mirroring"],
	)

	// Anti-detection options
	app.bypassCheckboxes["Anti-Debug Techniques"] = widget.NewCheck("Anti-Debug Techniques", func(checked bool) {
		app.antiDebugTechniques = checked
		app.logger.Info("Enhanced option changed", zap.String("option", "Anti-Debug Techniques"), zap.Bool("enabled", checked))
	})

	app.bypassCheckboxes["Anti-VM Techniques"] = widget.NewCheck("Anti-VM Techniques", func(checked bool) {
		app.antiVMTechniques = checked
		app.logger.Info("Enhanced option changed", zap.String("option", "Anti-VM Techniques"), zap.Bool("enabled", checked))
	})

	app.bypassCheckboxes["Delayed Execution"] = widget.NewCheck("Delayed Execution", func(checked bool) {
		app.delayedExecution = checked
		app.logger.Info("Enhanced option changed", zap.String("option", "Delayed Execution"), zap.Bool("enabled", checked))
	})

	// Anti-detection options row
	enhancedAntiDetectionOptions := container.NewGridWithColumns(3,
		app.bypassCheckboxes["Anti-Debug Techniques"],
		app.bypassCheckboxes["Anti-VM Techniques"],
		app.bypassCheckboxes["Delayed Execution"],
	)

	// Create ultra compact spacer for enhanced options
	enhancedSpacerFunc := func() fyne.CanvasObject {
		spacer := container.NewVBox()
		spacer.Resize(fyne.NewSize(0, 1)) // Minimal spacing between enhanced option rows
		return spacer
	}

	// Ultra compact enhanced options section
	enhancedCard := ModernSection("Enhanced Options", container.NewVBox(
		enhancedMemoryOptions,
		enhancedSpacerFunc(),
		enhancedThreadOptions,
		enhancedSpacerFunc(),
		enhancedProcessOptions,
		enhancedSpacerFunc(),
		enhancedAntiDetectionOptions,
	))

	// Ultra compact advanced options section
	advancedCard := ModernSection("Advanced Options", container.NewVBox(
		advancedOptions1,
		enhancedSpacerFunc(),
		advancedOptions2,
		enhancedSpacerFunc(),
		enhancedCard,
	))

	// Create ultra compact spacer for bypass options
	bypassSpacerFunc := func() fyne.CanvasObject {
		spacer := container.NewVBox()
		spacer.Resize(fyne.NewSize(0, 1)) // Minimal spacing between bypass sections
		return spacer
	}

	// Combine all anti-detection option cards with ultra compact spacing
	bypassCard := container.NewVBox(
		bypassTitleContainer,
		bypassSpacerFunc(),
		loadingCard,
		bypassSpacerFunc(),
		memoryCard,
		bypassSpacerFunc(),
		advancedCard,
	)

	// Initial option state setup
	app.updateBypassOptionsState()

	// Target process selection with inline label design
	selectProcessButton := CompactButton("Select Process", func() {
		// Create a larger dialog
		processDialog := dialog.NewCustom("Select Target Process", "Close", app.createRightPanel(), app.mainWindow)
		processDialog.Resize(fyne.NewSize(500, 600)) // Adjust to a more suitable size, increase height to show more processes
		processDialog.Show()
	})
	selectProcessButton.Importance = widget.MediumImportance

	// Display currently selected process information
	app.selectedProcessLabel = widget.NewLabel("No Process Selected")
	if app.selectedPID > 0 {
		app.selectedProcessLabel.SetText(fmt.Sprintf("%s (PID: %d)", app.selectedProc, app.selectedPID))
	}

	// Create compact target process selector with inline label
	processSelector := InlineLabelButton("Target Process:", selectProcessButton, app.selectedProcessLabel)

	// Create a simple card for the process selector
	processCard := NewCard(processSelector, false)

	// Inject button - use light blue
	injectButton := widget.NewButton("Inject", func() {
		dllPath, _ := app.selectedDll.Get()
		if dllPath == "" {
			app.logger.Error("Injection failed", zap.String("reason", "No DLL file selected"))
			dialog.ShowError(fmt.Errorf("Please select a DLL file"), app.mainWindow)
			return
		}

		if app.selectedPID <= 0 {
			app.logger.Error("Injection failed", zap.String("reason", "No target process selected"))
			dialog.ShowError(fmt.Errorf("Please select a target process"), app.mainWindow)
			return
		}

		app.logger.Info("Starting DLL injection",
			zap.String("DLL", dllPath),
			zap.String("Process", app.selectedProc),
			zap.Int32("PID", app.selectedPID),
			zap.Int("Method", app.injectionMethod),
		)

		// Create injector instance
		loggerAdapter := NewLoggerAdapter(app.logger)
		inj := injector.NewInjector(dllPath, uint32(app.selectedPID), loggerAdapter)

		// Set injection method
		inj.SetMethod(injector.InjectionMethod(app.injectionMethod))

		// Set anti-detection options
		options := injector.BypassOptions{
			MemoryLoad:             app.memoryLoad,
			ErasePEHeader:          app.peHeaderErasure,
			EraseEntryPoint:        app.entryPointErase,
			ManualMapping:          app.manualMapping,
			InvisibleMemory:        app.invisibleMemory,
			PathSpoofing:           app.pathSpoofing,
			LegitProcessInjection:  app.legitProcessInjection,
			PTESpoofing:            app.pteSpoofing,
			VADManipulation:        app.vadManipulation,
			RemoveVADNode:          app.removeVADNode,
			AllocBehindThreadStack: app.allocBehindThreadStack,
			DirectSyscalls:         app.directSyscalls,
		}
		inj.SetBypassOptions(options)

		// Set enhanced options if available
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

		// Execute injection operation
		go func() {
			// Run injection in background thread to avoid UI freezing
			err := inj.Inject()

			// Update UI in main thread
			fyne.Do(func() {
				if err != nil {
					app.logger.Error("Injection failed", zap.Error(err))
					dialog.ShowError(fmt.Errorf("Injection failed: %v", err), app.mainWindow)
				} else {
					app.logger.Info("Injection successful",
						zap.String("DLL", dllPath),
						zap.String("Process", app.selectedProc),
						zap.Int32("PID", app.selectedPID))
					dialog.ShowInformation("Injection Successful", "DLL has been successfully injected into the target process", app.mainWindow)
				}
			})
		}()
	})
	injectButton.Importance = widget.HighImportance

	// Make the inject button more prominent with modern styling
	injectButton.Alignment = widget.ButtonAlignCenter

	// Create a compact inject button container for VS Code style
	injectButtonContainer := container.NewVBox(
		container.NewHBox(
			layout.NewSpacer(),
			injectButton,
			layout.NewSpacer(),
		),
	)

	// Create ultra compact spacers for VS Code style layout
	compactSpacer := func() fyne.CanvasObject {
		spacer := container.NewVBox()
		spacer.Resize(fyne.NewSize(0, 2)) // Ultra minimal spacing between major sections
		return spacer
	}

	// Use scroll container to wrap all content with compact spacing
	scrollContent := container.NewVBox(
		dllCard,
		compactSpacer(),
		processCard,
		compactSpacer(),
		methodCard,
		compactSpacer(),
		bypassCard,
		compactSpacer(),
		injectButtonContainer,
	)

	// Return scrollable content
	return container.NewScroll(scrollContent)
}

// updateBypassOptionsState 更新反检测选项的互斥状态
func (app *Application) updateBypassOptionsState() {
	// When there are incompatible option combinations, save them here
	var incompatibilities []string

	// Manual mapping requires memory loading
	if app.manualMapping {
		app.memoryLoad = true
		app.bypassCheckboxes["Load DLL from Memory"].SetChecked(true)
		app.bypassCheckboxes["Load DLL from Memory"].Disable()
	} else {
		app.bypassCheckboxes["Load DLL from Memory"].Enable()
	}

	// Hidden memory region only valid with manual mapping
	if !app.manualMapping {
		app.invisibleMemory = false
		app.bypassCheckboxes["Map to Hidden Memory"].SetChecked(false)
		app.bypassCheckboxes["Map to Hidden Memory"].Disable()
	} else {
		app.bypassCheckboxes["Map to Hidden Memory"].Enable()
	}

	// Early Bird and Cryo Bird injection don't need target process selection, restart the process
	if app.injectionMethod == int(injector.EarlyBirdAPCInjection) ||
		app.injectionMethod == int(injector.CryoBirdInjection) {
		// Legitimate process injection not applicable to these methods
		if app.legitProcessInjection {
			incompatibilities = append(incompatibilities, fmt.Sprintf(
				"'Use Legitimate Process' is not compatible with '%s' injection method",
				app.selectedMethod,
			))
		}

		app.legitProcessInjection = false
		app.bypassCheckboxes["Use Legitimate Process"].SetChecked(false)
		app.bypassCheckboxes["Use Legitimate Process"].Disable()
	} else {
		app.bypassCheckboxes["Use Legitimate Process"].Enable()
	}

	// Path spoofing and memory loading are mutually exclusive
	if app.memoryLoad && app.pathSpoofing {
		incompatibilities = append(incompatibilities, "'Path Spoofing' is not compatible with 'Load DLL from Memory'")
	}

	if app.memoryLoad {
		app.pathSpoofing = false
		app.bypassCheckboxes["Path Spoofing"].SetChecked(false)
		app.bypassCheckboxes["Path Spoofing"].Disable()
	} else {
		app.bypassCheckboxes["Path Spoofing"].Enable()
	}

	// PTE and VAD are mutually exclusive
	if app.pteSpoofing && app.vadManipulation {
		incompatibilities = append(incompatibilities, "'PTE Modification' is not compatible with 'VAD Manipulation'")
	}

	if app.pteSpoofing {
		app.bypassCheckboxes["VAD Manipulation"].Disable()
		app.bypassCheckboxes["Remove VAD Node"].Disable()
	} else {
		app.bypassCheckboxes["VAD Manipulation"].Enable()
		// Remove VAD node is only available when VAD manipulation is enabled
		if app.vadManipulation {
			app.bypassCheckboxes["Remove VAD Node"].Enable()
		} else {
			app.bypassCheckboxes["Remove VAD Node"].Disable()
		}
	}

	// Enhanced options mutual exclusivity checks

	// Process hollowing and process doppelganging are mutually exclusive
	if app.processHollowing && app.doppelgangingProcess {
		incompatibilities = append(incompatibilities, "'Process Hollowing' is not compatible with 'Process Doppelganging'")

		// Default to keeping Process Hollowing and disabling Process Doppelganging
		app.doppelgangingProcess = false
		app.bypassCheckboxes["Process Doppelganging"].SetChecked(false)
	}

	// Thread hijacking and stealthy threads are mutually exclusive
	if app.threadHijacking && app.stealthyThreads {
		incompatibilities = append(incompatibilities, "'Thread Hijacking' is not compatible with 'Stealthy Threads'")

		// Default to keeping Thread Hijacking and disabling Stealthy Threads
		app.stealthyThreads = false
		app.bypassCheckboxes["Stealthy Threads"].SetChecked(false)
	}

	// Process hollowing requires memory loading
	if app.processHollowing && !app.memoryLoad {
		app.memoryLoad = true
		app.bypassCheckboxes["Load DLL from Memory"].SetChecked(true)
		incompatibilities = append(incompatibilities, "'Process Hollowing' requires 'Load DLL from Memory'")
	}

	// Process doppelganging requires memory loading
	if app.doppelgangingProcess && !app.memoryLoad {
		app.memoryLoad = true
		app.bypassCheckboxes["Load DLL from Memory"].SetChecked(true)
		incompatibilities = append(incompatibilities, "'Process Doppelganging' requires 'Load DLL from Memory'")
	}

	// Thread hijacking requires memory loading
	if app.threadHijacking && !app.memoryLoad {
		app.memoryLoad = true
		app.bypassCheckboxes["Load DLL from Memory"].SetChecked(true)
		incompatibilities = append(incompatibilities, "'Thread Hijacking' requires 'Load DLL from Memory'")
	}

	// Multi-stage injection requires memory loading
	if app.multiStageInjection && !app.memoryLoad {
		app.memoryLoad = true
		app.bypassCheckboxes["Load DLL from Memory"].SetChecked(true)
		incompatibilities = append(incompatibilities, "'Multi-Stage Injection' requires 'Load DLL from Memory'")
	}

	// Memory fluctuation is only applicable with memory loading
	if app.memoryFluctuation && !app.memoryLoad {
		app.memoryLoad = true
		app.bypassCheckboxes["Load DLL from Memory"].SetChecked(true)
		incompatibilities = append(incompatibilities, "'Memory Fluctuation' requires 'Load DLL from Memory'")
	}

	// APC queueing and standard injection are not compatible
	if app.apcQueueing && app.injectionMethod == int(injector.StandardInjection) {
		incompatibilities = append(incompatibilities, "'APC Queueing' is not compatible with 'Standard Injection'")
		app.apcQueueing = false
		app.bypassCheckboxes["APC Queueing"].SetChecked(false)
	}

	// Process hollowing and standard injection are not compatible
	if app.processHollowing && app.injectionMethod != int(injector.StandardInjection) {
		incompatibilities = append(incompatibilities, "'Process Hollowing' requires 'Standard Injection'")
		app.injectionMethod = int(injector.StandardInjection)
		app.selectedMethod = "Standard Injection"
		// Update radio button in UI
		// Find and update the radio group for injection method
		if content := app.mainWindow.Content(); content != nil {
			if scroll, ok := content.(*container.Scroll); ok && scroll.Content != nil {
				app.updateRadioGroupSelection(scroll.Content, "Standard Injection")
			}
		}
	}

	// If there are mutual conflicts, show warning dialog
	if len(incompatibilities) > 0 {
		message := "Detected the following mutually exclusive options:\n\n"
		for _, incomp := range incompatibilities {
			message += "• " + incomp + "\n"
		}
		message += "\nAutomatically adjusted to compatible option combinations."

		go func() {
			// Execute UI operations in main thread
			fyne.Do(func() {
				dialog.ShowInformation("Option Conflict Alert", message, app.mainWindow)

				app.logger.Warn("Detected mutually exclusive options",
					zap.Strings("conflicts", incompatibilities))
			})
		}()
	}
}

// dllFilter 实现fyne.io/fyne/v2/storage.FileFilter接口，用于过滤DLL文件
type dllFilter struct{}

// Matches 检查文件是否为DLL文件
func (f *dllFilter) Matches(uri fyne.URI) bool {
	return strings.HasSuffix(strings.ToLower(uri.Name()), ".dll")
}

// createRightPanel 创建右侧面板，显示进程列表
func (app *Application) createRightPanel() fyne.CanvasObject {
	// Search box
	app.searchEntry = SearchField("Search process name or PID...", func(query string) {
		app.filterProcesses(query)
	})

	// Refresh button
	refreshButton := CompactIconButton("", theme.ViewRefreshIcon(), func() {
		app.refreshProcessList()
		app.logger.Info("Process list refreshed")
	})

	// Search bar
	searchBar := container.NewBorder(nil, nil, nil, refreshButton, app.searchEntry)

	// Process list
	app.processList = widget.NewList(
		func() int {
			return len(app.processes)
		},
		func() fyne.CanvasObject {
			// Create a template item
			return ProcessListItem(process.ProcessEntry{
				PID:  0,
				Name: "Template Process",
			}, false)
		},
		func(id widget.ListItemID, item fyne.CanvasObject) {
			if id < 0 || id >= len(app.processes) {
				return
			}

			proc := app.processes[id]
			selected := proc.PID == app.selectedPID

			// Create new process list item
			newItem := ProcessListItem(proc, selected)

			// Get original container and replace content
			if container, ok := item.(*fyne.Container); ok {
				container.Objects = []fyne.CanvasObject{newItem}
				container.Refresh()
			}
		},
	)

	// Set selection handler
	app.processList.OnSelected = func(id widget.ListItemID) {
		if id < 0 || id >= len(app.processes) {
			return
		}
		app.selectedPID = app.processes[id].PID
		app.selectedProc = app.processes[id].Name
		app.logger.Info("Process selected",
			zap.String("name", app.selectedProc),
			zap.Int32("PID", app.selectedPID),
		)

		// Update process info display
		if app.selectedProcessLabel != nil {
			app.selectedProcessLabel.SetText(fmt.Sprintf("%s (PID: %d)", app.selectedProc, app.selectedPID))
		}

		// Close dialog
		app.mainWindow.Canvas().Overlays().Top().Hide()

		// Refresh list to update selected state
		app.processList.Refresh()
	}

	// Process list title and search bar
	header := container.NewVBox(
		SectionTitle("Process List"),
		searchBar,
	)

	// Use fixed-height container to wrap process list
	// Create a tall enough scroll container
	scrollContainer := container.NewScroll(app.processList)
	scrollContainer.SetMinSize(fyne.NewSize(400, 450)) // Set minimum size

	// Process list content
	content := container.NewBorder(
		header,
		nil, nil, nil,
		container.NewPadded(scrollContainer),
	)

	return content
}

// refreshProcessList 刷新进程列表
func (app *Application) refreshProcessList() {
	if err := app.processInfo.Refresh(); err != nil {
		app.logger.Error("Refresh process list failed", zap.Error(err))
		dialog.ShowError(fmt.Errorf("Refresh process list failed: %v", err), app.mainWindow)
		return
	}

	app.processes = app.processInfo.GetProcesses()
	app.logger.Info("Process list refreshed", zap.Int("Process count", len(app.processes)))
	if app.processList != nil {
		app.filterProcesses(app.searchEntry.Text)
		app.processList.Refresh()
	}
}

// filterProcesses 过滤进程列表
func (app *Application) filterProcesses(query string) {
	if query == "" {
		app.processes = app.processInfo.GetProcesses()
	} else {
		allProcesses := app.processInfo.GetProcesses()
		app.processes = make([]process.ProcessEntry, 0, len(allProcesses))

		lowerQuery := strings.ToLower(query)
		for _, p := range allProcesses {
			if strings.Contains(strings.ToLower(p.Name), lowerQuery) ||
				strings.Contains(strings.ToLower(p.Executable), lowerQuery) ||
				strings.Contains(strconv.FormatInt(int64(p.PID), 10), lowerQuery) {
				app.processes = append(app.processes, p)
			}
		}

		app.logger.Info("Filter process list",
			zap.String("Search term", query),
			zap.Int("Match count", len(app.processes)),
		)
	}

	if app.processList != nil {
		app.processList.Refresh()
	}
}

// updateLogTextArea 更新日志文本区域
func (app *Application) updateLogTextArea() {
	if app.consoleLog == nil || app.consoleView == nil {
		return
	}

	// Get all log entries
	length := app.consoleLog.binding.Length()
	logs := make([]string, length)
	for i := 0; i < length; i++ {
		logs[i], _ = app.consoleLog.binding.GetValue(i)
	}

	// Combine logs into a single string, ensure each line has a newline
	logText := strings.Join(logs, "\n")

	// Update text area in main thread
	fyne.Do(func() {
		// Directly set text content
		app.consoleView.SetText(logText)
		// Force refresh to ensure the content is updated
		app.consoleView.Refresh()

		// Also refresh the scroll container to update its content size
		if app.scrollContainer != nil {
			app.scrollContainer.Refresh()

			// Ensure scroll position is at the bottom
			app.ensureScrollToBottom()
		}
	})
}

// ensureScrollToBottom 确保滚动到底部
func (app *Application) ensureScrollToBottom() {
	if app.scrollContainer == nil {
		return
	}

	// Get the content size and scroll container size
	contentSize := app.consoleView.MinSize()
	containerSize := app.scrollContainer.Size()

	// Calculate the maximum scroll position
	maxScroll := contentSize.Height - containerSize.Height
	if maxScroll < 0 {
		maxScroll = 0
	}

	// Scroll to the bottom
	app.scrollContainer.Offset = fyne.NewPos(0, maxScroll)
	app.scrollContainer.Refresh()
}

// updateRadioGroupSelection recursively searches for and updates radio group selection
func (app *Application) updateRadioGroupSelection(obj fyne.CanvasObject, selection string) {
	if radio, ok := obj.(*widget.RadioGroup); ok {
		radio.SetSelected(selection)
		return
	}

	if container, ok := obj.(*fyne.Container); ok {
		for _, child := range container.Objects {
			app.updateRadioGroupSelection(child, selection)
		}
	}
}

// Close 关闭应用程序
func (app *Application) Close() {
	app.logger.Info("Application closed")

	// Sync logs
	if app.logger != nil {
		_ = app.logger.Sync()
	}

	// Clean up binding listeners
	if app.logListener != nil {
		app.consoleLog.binding.RemoveListener(app.logListener)
	}

	if app.mainWindow != nil {
		app.mainWindow.Close()
	}
}
