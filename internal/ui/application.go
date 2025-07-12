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

// WriteLog 为zapcore实现的日志写入 - 用户友好版本
func (c *consoleLog) WriteLog(enc zapcore.Encoder, entry zapcore.Entry, fields []zapcore.Field) error {
	// 过滤掉不重要的日志消息
	if c.shouldSkipMessage(entry.Message, fields) {
		return nil
	}

	// 格式化用户友好的消息
	message := c.formatUserFriendlyMessage(entry.Message, entry.Level, fields)
	if message == "" {
		return nil
	}

	// 添加时间戳
	timestamp := time.Now().Format("15:04")
	text := fmt.Sprintf("%s %s", timestamp, message)

	// 使用通用方法添加日志
	c.addLogEntry(text)

	return nil
}

// shouldSkipMessage 判断是否应该跳过某些日志消息
func (c *consoleLog) shouldSkipMessage(message string, fields []zapcore.Field) bool {
	// 跳过bypass选项变化的日志（太频繁且不重要）
	if strings.Contains(message, "Anti-detection option changed") {
		return true
	}

	// 跳过兼容性检查的详细日志
	if strings.Contains(message, "Bypass option incompatibilities detected") {
		return true
	}

	// 跳过一些技术细节日志
	if strings.Contains(message, "PE Header/Entry Point erasure is most effective") {
		return true
	}

	return false
}

// formatUserFriendlyMessage 格式化用户友好的消息
func (c *consoleLog) formatUserFriendlyMessage(message string, level zapcore.Level, fields []zapcore.Field) string {
	// 根据消息类型返回用户友好的格式
	switch {
	case strings.Contains(message, "DLL Injector starting"):
		return "🚀 DLL注入器已启动"
	case strings.Contains(message, "DLL Injector started"):
		return "✅ 程序初始化完成"
	case strings.Contains(message, "Application closed"):
		return "👋 程序已关闭"
	case strings.Contains(message, "Injection method selected"):
		method := c.getFieldValue(fields, "method")
		return fmt.Sprintf("🔧 选择注入方式: %s", c.translateMethod(method))
	case strings.Contains(message, "Process selected"):
		name := c.getFieldValue(fields, "name")
		pid := c.getFieldValue(fields, "PID")
		return fmt.Sprintf("🎯 选择目标进程: %s (PID: %s)", name, pid)
	case strings.Contains(message, "Starting DLL injection"):
		dll := c.getFieldValue(fields, "DLL")
		process := c.getFieldValue(fields, "Process")
		return fmt.Sprintf("⚡ 开始注入: %s → %s", c.getFileName(dll), process)
	case strings.Contains(message, "Starting injection"):
		method := c.getFieldValue(fields, "method")
		return fmt.Sprintf("🔄 执行注入 (%s)", c.translateMethod(method))
	case strings.Contains(message, "Injection successful"):
		return "✅ 注入成功完成"
	case strings.Contains(message, "Injection failed"):
		if level == zapcore.ErrorLevel {
			reason := c.getFieldValue(fields, "reason")
			if reason != "" {
				return fmt.Sprintf("❌ 注入失败: %s", c.translateError(reason))
			}
			return "❌ 注入失败"
		}
	case strings.Contains(message, "Failed to read DLL file"):
		return "❌ 无法读取DLL文件"
	case strings.Contains(message, "Failed to open target process"):
		return "❌ 无法打开目标进程"
	case strings.Contains(message, "Manual mapping successful"):
		return "✅ 手动映射完成"
	case strings.Contains(message, "injection successful"):
		return "✅ 注入操作完成"
	}

	// 对于其他消息，如果是错误级别，显示简化版本
	if level == zapcore.ErrorLevel {
		return fmt.Sprintf("❌ %s", message)
	} else if level == zapcore.WarnLevel {
		return fmt.Sprintf("⚠️ %s", message)
	}

	// 默认返回空字符串（跳过）
	return ""
}

// getFieldValue 从字段中获取指定键的值
func (c *consoleLog) getFieldValue(fields []zapcore.Field, key string) string {
	for _, field := range fields {
		if field.Key == key {
			switch field.Type {
			case zapcore.StringType:
				return field.String
			case zapcore.Int64Type, zapcore.Int32Type:
				return strconv.FormatInt(field.Integer, 10)
			case zapcore.Uint64Type, zapcore.Uint32Type:
				return strconv.FormatUint(uint64(field.Integer), 10)
			default:
				return fmt.Sprintf("%v", field.Interface)
			}
		}
	}
	return ""
}

// translateMethod 翻译注入方法名称
func (c *consoleLog) translateMethod(method string) string {
	switch method {
	case "Standard Injection":
		return "标准注入"
	case "SetWindowsHookEx Injection":
		return "钩子注入"
	case "QueueUserAPC Injection":
		return "APC注入"
	case "Early Bird APC Injection":
		return "早鸟APC注入"
	case "DLL Notification Injection":
		return "DLL通知注入"
	case "Job Object Cold Injection":
		return "冷冻进程注入"
	default:
		return method
	}
}

// translateError 翻译错误信息
func (c *consoleLog) translateError(reason string) string {
	switch reason {
	case "No DLL file selected":
		return "未选择DLL文件"
	case "No target process selected":
		return "未选择目标进程"
	default:
		return reason
	}
}

// getFileName 从完整路径中提取文件名
func (c *consoleLog) getFileName(path string) string {
	if path == "" {
		return ""
	}
	// 提取文件名
	parts := strings.Split(path, "\\")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	parts = strings.Split(path, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return path
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
		height:           float32(height),
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
			app.logger.Info("Injection method selected", zap.String("method", "SetWindowsHookEx"))
		case "QueueUserAPC":
			app.injectionMethod = int(injector.QueueUserAPCInjection)
			app.logger.Info("Injection method selected", zap.String("method", "QueueUserAPC"))
		case "Early Bird":
			app.injectionMethod = int(injector.EarlyBirdAPCInjection)
			app.logger.Info("Injection method selected", zap.String("method", "Early Bird"))
		case "DLL Notification":
			app.injectionMethod = int(injector.DllNotificationInjection)
			app.logger.Info("Injection method selected", zap.String("method", "DLL Notification"))
		case "Job Object":
			app.injectionMethod = int(injector.CryoBirdInjection)
			app.logger.Info("Injection method selected", zap.String("method", "Job Object"))
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

	// Anti-detection options - 重新设计为紧凑的标签页界面
	bypassContainer := app.createCompactBypassOptions()

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
		)

		// Create injector instance
		loggerAdapter := NewLoggerAdapter(app.logger)
		inj := injector.NewInjector(dllPath, uint32(app.selectedPID), loggerAdapter)

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

	// Create ultra compact spacers for VS Code style layout
	compactSpacer := func() fyne.CanvasObject {
		spacer := container.NewVBox()
		spacer.Resize(fyne.NewSize(0, 2)) // Ultra minimal spacing between major sections
		return spacer
	}

	// Use compact container without scroll - 内容现在应该适合窗口
	content := container.NewVBox(
		dllCard,
		compactSpacer(),
		processCard,
		compactSpacer(),
		methodCard,
		compactSpacer(),
		bypassContainer,
		compactSpacer(),
		injectButton, // 直接使用按钮，不添加额外容器
	)

	// Return content directly without scroll
	return content
}

// updateBypassOptionsState 更新反检测选项的互斥状态
func (app *Application) updateBypassOptionsState() {
	// When there are incompatible option combinations, save them here
	var incompatibilities []string

	// First, apply injection method specific compatibility rules
	app.applyInjectionMethodCompatibility(&incompatibilities)

	// Then apply general bypass option compatibility rules
	app.applyGeneralBypassCompatibility(&incompatibilities)

	// Show incompatibilities if any
	if len(incompatibilities) > 0 {
		// 只在对话框中显示，不记录到日志（避免干扰）
		dialog.ShowInformation("Bypass Option Conflicts",
			fmt.Sprintf("Some bypass options were automatically adjusted due to conflicts:\n\n%s",
				strings.Join(incompatibilities, "\n")), app.mainWindow)
	}
}

// applyInjectionMethodCompatibility applies compatibility rules based on injection method
func (app *Application) applyInjectionMethodCompatibility(incompatibilities *[]string) {
	method := injector.InjectionMethod(app.injectionMethod)

	switch method {
	case injector.StandardInjection:
		app.applyStandardInjectionCompatibility(incompatibilities)
	case injector.SetWindowsHookExInjection:
		app.applySetWindowsHookExCompatibility(incompatibilities)
	case injector.QueueUserAPCInjection:
		app.applyQueueUserAPCCompatibility(incompatibilities)
	case injector.EarlyBirdAPCInjection:
		app.applyEarlyBirdAPCCompatibility(incompatibilities)
	case injector.DllNotificationInjection:
		app.applyDllNotificationCompatibility(incompatibilities)
	case injector.CryoBirdInjection:
		app.applyCryoBirdCompatibility(incompatibilities)
	}
}

// applyStandardInjectionCompatibility applies compatibility rules for Standard Injection
func (app *Application) applyStandardInjectionCompatibility(incompatibilities *[]string) {
	// Standard injection supports most bypass options
	// Enable all compatible options
	app.enableBypassOption("Load DLL from Memory")
	app.enableBypassOption("Erase PE Header")
	app.enableBypassOption("Erase Entry Point")
	app.enableBypassOption("Manual Mapping")
	app.enableBypassOption("Map to Hidden Memory")
	app.enableBypassOption("Path Spoofing")
	app.enableBypassOption("Use Legitimate Process")
	app.enableBypassOption("PTE Modification")
	app.enableBypassOption("VAD Manipulation")
	app.enableBypassOption("Remove VAD Node")
	app.enableBypassOption("Allocate Behind Thread Stack")
	app.enableBypassOption("Direct Syscalls")

	// Enhanced options
	app.enableBypassOption("Randomize Allocation")
	app.enableBypassOption("Delayed Execution")
	app.enableBypassOption("Multi-Stage Injection")
	app.enableBypassOption("Anti-Debug Techniques")
	app.enableBypassOption("Process Hollowing")
	app.enableBypassOption("Atom Bombing")
	app.enableBypassOption("Process Doppelganging")
	app.enableBypassOption("Ghost Writing")
	app.enableBypassOption("Module Stomping")
	app.enableBypassOption("Thread Hijacking")
	app.enableBypassOption("Memory Fluctuation")
	app.enableBypassOption("Anti-VM Techniques")
	app.enableBypassOption("Process Mirroring")
	app.enableBypassOption("Stealthy Threads")

	// APC Queueing is not compatible with Standard Injection
	if app.apcQueueing {
		*incompatibilities = append(*incompatibilities, "'APC Queueing' is not compatible with 'Standard Injection'")
		app.apcQueueing = false
		app.disableBypassOption("APC Queueing")
	} else {
		app.disableBypassOption("APC Queueing")
	}
}

// applySetWindowsHookExCompatibility applies compatibility rules for SetWindowsHookEx Injection
func (app *Application) applySetWindowsHookExCompatibility(incompatibilities *[]string) {
	// SetWindowsHookEx requires DLL file on disk, not compatible with memory-based options

	// Disable memory-based options
	if app.memoryLoad {
		*incompatibilities = append(*incompatibilities, "'Load DLL from Memory' is not compatible with 'SetWindowsHookEx Injection'")
		app.memoryLoad = false
		app.disableBypassOption("Load DLL from Memory")
	} else {
		app.disableBypassOption("Load DLL from Memory")
	}

	if app.manualMapping {
		*incompatibilities = append(*incompatibilities, "'Manual Mapping' is not compatible with 'SetWindowsHookEx Injection'")
		app.manualMapping = false
		app.disableBypassOption("Manual Mapping")
	} else {
		app.disableBypassOption("Manual Mapping")
	}

	if app.invisibleMemory {
		*incompatibilities = append(*incompatibilities, "'Map to Hidden Memory' is not compatible with 'SetWindowsHookEx Injection'")
		app.invisibleMemory = false
		app.disableBypassOption("Map to Hidden Memory")
	} else {
		app.disableBypassOption("Map to Hidden Memory")
	}

	// Disable process-specific options (hook affects all processes)
	if app.legitProcessInjection {
		*incompatibilities = append(*incompatibilities, "'Use Legitimate Process' is not compatible with 'SetWindowsHookEx Injection'")
		app.legitProcessInjection = false
		app.disableBypassOption("Use Legitimate Process")
	} else {
		app.disableBypassOption("Use Legitimate Process")
	}

	// Enable compatible options
	app.enableBypassOption("Path Spoofing")
	app.enableBypassOption("Erase PE Header")
	app.enableBypassOption("Erase Entry Point")
	app.enableBypassOption("Anti-Debug Techniques")
	app.enableBypassOption("Anti-VM Techniques")

	// Disable advanced memory manipulation options
	app.disableBypassOption("PTE Modification")
	app.disableBypassOption("VAD Manipulation")
	app.disableBypassOption("Remove VAD Node")
	app.disableBypassOption("Allocate Behind Thread Stack")
	app.disableBypassOption("Direct Syscalls")
	app.disableBypassOption("Process Hollowing")
	app.disableBypassOption("Thread Hijacking")
	app.disableBypassOption("Memory Fluctuation")
	app.disableBypassOption("APC Queueing")
}

// applyQueueUserAPCCompatibility applies compatibility rules for QueueUserAPC Injection
func (app *Application) applyQueueUserAPCCompatibility(incompatibilities *[]string) {
	// QueueUserAPC supports most options but has some limitations

	// Enable most bypass options
	app.enableBypassOption("Load DLL from Memory")
	app.enableBypassOption("Erase PE Header")
	app.enableBypassOption("Erase Entry Point")
	app.enableBypassOption("Manual Mapping")
	app.enableBypassOption("Map to Hidden Memory")
	app.enableBypassOption("Path Spoofing")
	app.enableBypassOption("Use Legitimate Process")
	app.enableBypassOption("PTE Modification")
	app.enableBypassOption("VAD Manipulation")
	app.enableBypassOption("Remove VAD Node")
	app.enableBypassOption("Allocate Behind Thread Stack")
	app.enableBypassOption("Direct Syscalls")

	// Enhanced APC-specific options
	app.enableBypassOption("APC Queueing")
	app.enableBypassOption("Thread Hijacking")
	app.enableBypassOption("Delayed Execution")
	app.enableBypassOption("Anti-Debug Techniques")
	app.enableBypassOption("Anti-VM Techniques")

	// Some advanced techniques may interfere with APC mechanism
	app.enableBypassOption("Randomize Allocation")
	app.enableBypassOption("Multi-Stage Injection")
	app.enableBypassOption("Memory Fluctuation")

	// Process hollowing not compatible with APC injection
	if app.processHollowing {
		*incompatibilities = append(*incompatibilities, "'Process Hollowing' is not compatible with 'QueueUserAPC Injection'")
		app.processHollowing = false
		app.disableBypassOption("Process Hollowing")
	} else {
		app.disableBypassOption("Process Hollowing")
	}
}

// applyEarlyBirdAPCCompatibility applies compatibility rules for Early Bird APC Injection
func (app *Application) applyEarlyBirdAPCCompatibility(incompatibilities *[]string) {
	// Early Bird APC creates new process, so some options don't apply

	// Legitimate process injection not applicable (creates new process)
	if app.legitProcessInjection {
		*incompatibilities = append(*incompatibilities, "'Use Legitimate Process' is not compatible with 'Early Bird APC Injection'")
		app.legitProcessInjection = false
		app.disableBypassOption("Use Legitimate Process")
	} else {
		app.disableBypassOption("Use Legitimate Process")
	}

	// Enable compatible options
	app.enableBypassOption("Load DLL from Memory")
	app.enableBypassOption("Erase PE Header")
	app.enableBypassOption("Erase Entry Point")
	app.enableBypassOption("Manual Mapping")
	app.enableBypassOption("Map to Hidden Memory")
	app.enableBypassOption("Path Spoofing")
	app.enableBypassOption("PTE Modification")
	app.enableBypassOption("VAD Manipulation")
	app.enableBypassOption("Remove VAD Node")
	app.enableBypassOption("Allocate Behind Thread Stack")
	app.enableBypassOption("Direct Syscalls")

	// Enhanced options that work well with Early Bird
	app.enableBypassOption("APC Queueing")
	app.enableBypassOption("Randomize Allocation")
	app.enableBypassOption("Delayed Execution")
	app.enableBypassOption("Multi-Stage Injection")
	app.enableBypassOption("Anti-Debug Techniques")
	app.enableBypassOption("Process Hollowing") // Can be combined
	app.enableBypassOption("Thread Hijacking")
	app.enableBypassOption("Memory Fluctuation")
	app.enableBypassOption("Anti-VM Techniques")
	app.enableBypassOption("Process Mirroring")
	app.enableBypassOption("Stealthy Threads")
}

// applyDllNotificationCompatibility applies compatibility rules for DLL Notification Injection
func (app *Application) applyDllNotificationCompatibility(incompatibilities *[]string) {
	// DLL Notification currently uses standard injection internally
	// Apply similar rules as standard injection but with some limitations

	app.enableBypassOption("Load DLL from Memory")
	app.enableBypassOption("Erase PE Header")
	app.enableBypassOption("Erase Entry Point")
	app.enableBypassOption("Manual Mapping")
	app.enableBypassOption("Map to Hidden Memory")
	app.enableBypassOption("Path Spoofing")
	app.enableBypassOption("Use Legitimate Process")
	app.enableBypassOption("PTE Modification")
	app.enableBypassOption("VAD Manipulation")
	app.enableBypassOption("Remove VAD Node")
	app.enableBypassOption("Allocate Behind Thread Stack")
	app.enableBypassOption("Direct Syscalls")

	// Enhanced options
	app.enableBypassOption("Randomize Allocation")
	app.enableBypassOption("Delayed Execution")
	app.enableBypassOption("Multi-Stage Injection")
	app.enableBypassOption("Anti-Debug Techniques")
	app.enableBypassOption("Thread Hijacking")
	app.enableBypassOption("Memory Fluctuation")
	app.enableBypassOption("Anti-VM Techniques")

	// APC-related options not applicable
	app.disableBypassOption("APC Queueing")

	// Process hollowing may interfere with notification mechanism
	if app.processHollowing {
		*incompatibilities = append(*incompatibilities, "'Process Hollowing' may interfere with 'DLL Notification Injection'")
		app.processHollowing = false
		app.disableBypassOption("Process Hollowing")
	} else {
		app.disableBypassOption("Process Hollowing")
	}
}

// applyCryoBirdCompatibility applies compatibility rules for Job Object (CryoBird) Injection
func (app *Application) applyCryoBirdCompatibility(incompatibilities *[]string) {
	// CryoBird freezes existing process, then uses standard injection
	// Similar to standard injection but with some limitations

	// Legitimate process injection not applicable (targets existing process)
	if app.legitProcessInjection {
		*incompatibilities = append(*incompatibilities, "'Use Legitimate Process' is not compatible with 'Job Object Injection'")
		app.legitProcessInjection = false
		app.disableBypassOption("Use Legitimate Process")
	} else {
		app.disableBypassOption("Use Legitimate Process")
	}

	// Enable most bypass options
	app.enableBypassOption("Load DLL from Memory")
	app.enableBypassOption("Erase PE Header")
	app.enableBypassOption("Erase Entry Point")
	app.enableBypassOption("Manual Mapping")
	app.enableBypassOption("Map to Hidden Memory")
	app.enableBypassOption("Path Spoofing")
	app.enableBypassOption("PTE Modification")
	app.enableBypassOption("VAD Manipulation")
	app.enableBypassOption("Remove VAD Node")
	app.enableBypassOption("Allocate Behind Thread Stack")
	app.enableBypassOption("Direct Syscalls")

	// Enhanced options that work with frozen process
	app.enableBypassOption("Randomize Allocation")
	app.enableBypassOption("Delayed Execution")
	app.enableBypassOption("Multi-Stage Injection")
	app.enableBypassOption("Anti-Debug Techniques")
	app.enableBypassOption("Thread Hijacking")
	app.enableBypassOption("Memory Fluctuation")
	app.enableBypassOption("Anti-VM Techniques")
	app.enableBypassOption("Process Mirroring")
	app.enableBypassOption("Stealthy Threads")

	// APC options not applicable (process is frozen)
	app.disableBypassOption("APC Queueing")

	// Process hollowing not applicable (targets existing process)
	if app.processHollowing {
		*incompatibilities = append(*incompatibilities, "'Process Hollowing' is not compatible with 'Job Object Injection'")
		app.processHollowing = false
		app.disableBypassOption("Process Hollowing")
	} else {
		app.disableBypassOption("Process Hollowing")
	}
}

// applyGeneralBypassCompatibility applies general bypass option compatibility rules
func (app *Application) applyGeneralBypassCompatibility(incompatibilities *[]string) {
	// Manual mapping requires memory loading
	if app.manualMapping {
		app.memoryLoad = true
		app.bypassCheckboxes["Load DLL from Memory"].SetChecked(true)
		app.bypassCheckboxes["Load DLL from Memory"].Disable()
	}

	// Hidden memory region only valid with manual mapping
	if !app.manualMapping {
		if app.invisibleMemory {
			*incompatibilities = append(*incompatibilities, "'Map to Hidden Memory' requires 'Manual Mapping' to be enabled")
			app.invisibleMemory = false
			app.disableBypassOption("Map to Hidden Memory")
		} else {
			app.disableBypassOption("Map to Hidden Memory")
		}
	}

	// Memory load and path spoofing are mutually exclusive
	if app.memoryLoad && app.pathSpoofing {
		*incompatibilities = append(*incompatibilities, "'Load DLL from Memory' and 'Path Spoofing' are mutually exclusive")
		app.pathSpoofing = false
		app.bypassCheckboxes["Path Spoofing"].SetChecked(false)
	}

	// PE header and entry point erasure work best with manual mapping
	if (app.peHeaderErasure || app.entryPointErase) && !app.manualMapping {
		// Don't force disable, but warn that it's less effective
		app.logger.Warn("PE Header/Entry Point erasure is most effective with Manual Mapping enabled")
	}

	// Advanced memory techniques require manual mapping for full effectiveness
	advancedMemoryOptions := []string{"PTE Modification", "VAD Manipulation", "Remove VAD Node"}
	for _, option := range advancedMemoryOptions {
		if app.isOptionEnabled(option) && !app.manualMapping {
			app.logger.Warn(fmt.Sprintf("%s is most effective with Manual Mapping enabled", option))
		}
	}

	// Process hollowing and thread hijacking are mutually exclusive
	if app.processHollowing && app.threadHijacking {
		*incompatibilities = append(*incompatibilities, "'Process Hollowing' and 'Thread Hijacking' are mutually exclusive")
		app.threadHijacking = false
		app.bypassCheckboxes["Thread Hijacking"].SetChecked(false)
	}
}

// enableBypassOption enables a bypass option checkbox
func (app *Application) enableBypassOption(optionName string) {
	if checkbox, exists := app.bypassCheckboxes[optionName]; exists {
		checkbox.Enable()
	}
}

// disableBypassOption disables a bypass option checkbox and unchecks it
func (app *Application) disableBypassOption(optionName string) {
	if checkbox, exists := app.bypassCheckboxes[optionName]; exists {
		checkbox.SetChecked(false)
		checkbox.Disable()

		// Update corresponding boolean field
		switch optionName {
		case "Load DLL from Memory":
			app.memoryLoad = false
		case "Erase PE Header":
			app.peHeaderErasure = false
		case "Erase Entry Point":
			app.entryPointErase = false
		case "Manual Mapping":
			app.manualMapping = false
		case "Map to Hidden Memory":
			app.invisibleMemory = false
		case "Path Spoofing":
			app.pathSpoofing = false
		case "Use Legitimate Process":
			app.legitProcessInjection = false
		case "PTE Modification":
			app.pteSpoofing = false
		case "VAD Manipulation":
			app.vadManipulation = false
		case "Remove VAD Node":
			app.removeVADNode = false
		case "Allocate Behind Thread Stack":
			app.allocBehindThreadStack = false
		case "Direct Syscalls":
			app.directSyscalls = false
		case "Randomize Allocation":
			app.randomizeAllocation = false
		case "Delayed Execution":
			app.delayedExecution = false
		case "Multi-Stage Injection":
			app.multiStageInjection = false
		case "Anti-Debug Techniques":
			app.antiDebugTechniques = false
		case "Process Hollowing":
			app.processHollowing = false
		case "Atom Bombing":
			app.atomBombing = false
		case "Process Doppelganging":
			app.doppelgangingProcess = false
		case "Ghost Writing":
			app.ghostWriting = false
		case "Module Stomping":
			app.moduleStomping = false
		case "Thread Hijacking":
			app.threadHijacking = false
		case "APC Queueing":
			app.apcQueueing = false
		case "Memory Fluctuation":
			app.memoryFluctuation = false
		case "Anti-VM Techniques":
			app.antiVMTechniques = false
		case "Process Mirroring":
			app.processMirroring = false
		case "Stealthy Threads":
			app.stealthyThreads = false
		}
	}
}

// isOptionEnabled checks if a bypass option is currently enabled
func (app *Application) isOptionEnabled(optionName string) bool {
	switch optionName {
	case "Load DLL from Memory":
		return app.memoryLoad
	case "Erase PE Header":
		return app.peHeaderErasure
	case "Erase Entry Point":
		return app.entryPointErase
	case "Manual Mapping":
		return app.manualMapping
	case "Map to Hidden Memory":
		return app.invisibleMemory
	case "Path Spoofing":
		return app.pathSpoofing
	case "Use Legitimate Process":
		return app.legitProcessInjection
	case "PTE Modification":
		return app.pteSpoofing
	case "VAD Manipulation":
		return app.vadManipulation
	case "Remove VAD Node":
		return app.removeVADNode
	case "Allocate Behind Thread Stack":
		return app.allocBehindThreadStack
	case "Direct Syscalls":
		return app.directSyscalls
	case "Randomize Allocation":
		return app.randomizeAllocation
	case "Delayed Execution":
		return app.delayedExecution
	case "Multi-Stage Injection":
		return app.multiStageInjection
	case "Anti-Debug Techniques":
		return app.antiDebugTechniques
	case "Process Hollowing":
		return app.processHollowing
	case "Atom Bombing":
		return app.atomBombing
	case "Process Doppelganging":
		return app.doppelgangingProcess
	case "Ghost Writing":
		return app.ghostWriting
	case "Module Stomping":
		return app.moduleStomping
	case "Thread Hijacking":
		return app.threadHijacking
	case "APC Queueing":
		return app.apcQueueing
	case "Memory Fluctuation":
		return app.memoryFluctuation
	case "Anti-VM Techniques":
		return app.antiVMTechniques
	case "Process Mirroring":
		return app.processMirroring
	case "Stealthy Threads":
		return app.stealthyThreads
	default:
		return false
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

// createCompactBypassOptions 创建超紧凑的反检测选项界面
func (app *Application) createCompactBypassOptions() fyne.CanvasObject {
	// 创建标题
	titleLabel := widget.NewLabelWithStyle("🛡️ Anti-Detection Options", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	// 创建超紧凑的标签页
	tabs := container.NewAppTabs()
	tabs.SetTabLocation(container.TabLocationTop)

	// 基础选项标签页 - 使用更紧凑的布局
	basicTab := app.createUltraCompactBasicTab()
	tabs.Append(container.NewTabItem("基础", basicTab))

	// 高级选项标签页
	advancedTab := app.createUltraCompactAdvancedTab()
	tabs.Append(container.NewTabItem("高级", advancedTab))

	// 预设配置标签页
	presetTab := app.createUltraCompactPresetTab()
	tabs.Append(container.NewTabItem("预设", presetTab))

	// 主容器 - 直接显示，不折叠
	mainContainer := container.NewVBox(
		titleLabel,
		tabs,
	)

	return widget.NewCard("", "", mainContainer)
}

// createUltraCompactBasicTab 创建超紧凑的基础选项标签页
func (app *Application) createUltraCompactBasicTab() fyne.CanvasObject {
	// 初始化checkbox映射
	if app.bypassCheckboxes == nil {
		app.bypassCheckboxes = make(map[string]*widget.Check)
	}

	// 创建紧凑的checkbox，去掉多余的文字
	app.bypassCheckboxes["Load DLL from Memory"] = widget.NewCheck("内存加载", func(checked bool) {
		app.memoryLoad = checked
		app.updateBypassOptionsState()
	})

	app.bypassCheckboxes["Use Manual Mapping"] = widget.NewCheck("手动映射", func(checked bool) {
		app.manualMapping = checked
		if checked {
			app.memoryLoad = true
			app.bypassCheckboxes["Load DLL from Memory"].SetChecked(true)
		}
		app.updateBypassOptionsState()
	})

	app.bypassCheckboxes["Erase PE Header"] = widget.NewCheck("擦除PE头", func(checked bool) {
		app.peHeaderErasure = checked
	})

	app.bypassCheckboxes["Path Spoofing"] = widget.NewCheck("路径伪装", func(checked bool) {
		app.pathSpoofing = checked
	})

	app.bypassCheckboxes["Use Legitimate Process"] = widget.NewCheck("合法进程", func(checked bool) {
		app.legitProcessInjection = checked
	})

	app.bypassCheckboxes["Erase Entry Point"] = widget.NewCheck("擦除入口", func(checked bool) {
		app.entryPointErase = checked
	})

	// 使用3列网格布局，最大化空间利用
	return container.NewGridWithColumns(3,
		app.bypassCheckboxes["Load DLL from Memory"],
		app.bypassCheckboxes["Use Manual Mapping"],
		app.bypassCheckboxes["Erase PE Header"],
		app.bypassCheckboxes["Path Spoofing"],
		app.bypassCheckboxes["Use Legitimate Process"],
		app.bypassCheckboxes["Erase Entry Point"],
	)
}

// createUltraCompactAdvancedTab 创建超紧凑的高级选项标签页
func (app *Application) createUltraCompactAdvancedTab() fyne.CanvasObject {
	// 创建所有高级选项的checkbox
	app.bypassCheckboxes["PTE Modification"] = widget.NewCheck("PTE修改", func(checked bool) {
		app.pteSpoofing = checked
		if checked && app.vadManipulation {
			app.vadManipulation = false
			app.bypassCheckboxes["VAD Manipulation"].SetChecked(false)
		}
	})

	app.bypassCheckboxes["VAD Manipulation"] = widget.NewCheck("VAD操作", func(checked bool) {
		app.vadManipulation = checked
		if checked && app.pteSpoofing {
			app.pteSpoofing = false
			app.bypassCheckboxes["PTE Modification"].SetChecked(false)
		}
	})

	app.bypassCheckboxes["Remove VAD Node"] = widget.NewCheck("移除VAD", func(checked bool) {
		app.removeVADNode = checked
		if checked && !app.vadManipulation {
			app.vadManipulation = true
			app.bypassCheckboxes["VAD Manipulation"].SetChecked(true)
			if app.pteSpoofing {
				app.pteSpoofing = false
				app.bypassCheckboxes["PTE Modification"].SetChecked(false)
			}
		}
	})

	app.bypassCheckboxes["Direct Syscalls"] = widget.NewCheck("直接调用", func(checked bool) {
		app.directSyscalls = checked
	})

	app.bypassCheckboxes["Allocate Behind Thread Stack"] = widget.NewCheck("线程栈", func(checked bool) {
		app.allocBehindThreadStack = checked
	})

	app.bypassCheckboxes["Anti-Debug Techniques"] = widget.NewCheck("反调试", func(checked bool) {
		app.antiDebugTechniques = checked
	})

	app.bypassCheckboxes["Anti-VM Techniques"] = widget.NewCheck("反虚拟机", func(checked bool) {
		app.antiVMTechniques = checked
	})

	app.bypassCheckboxes["Process Hollowing"] = widget.NewCheck("进程挖空", func(checked bool) {
		app.processHollowing = checked
		if checked && app.doppelgangingProcess {
			app.doppelgangingProcess = false
			app.bypassCheckboxes["Process Doppelganging"].SetChecked(false)
		}
	})

	app.bypassCheckboxes["Thread Hijacking"] = widget.NewCheck("线程劫持", func(checked bool) {
		app.threadHijacking = checked
		if checked && app.stealthyThreads {
			app.stealthyThreads = false
			app.bypassCheckboxes["Stealthy Threads"].SetChecked(false)
		}
	})

	// 添加缺失的checkbox
	app.bypassCheckboxes["Map to Hidden Memory"] = widget.NewCheck("隐藏内存", func(checked bool) {
		app.invisibleMemory = checked
	})

	app.bypassCheckboxes["Process Doppelganging"] = widget.NewCheck("进程替身", func(checked bool) {
		app.doppelgangingProcess = checked
		if checked && app.processHollowing {
			app.processHollowing = false
			app.bypassCheckboxes["Process Hollowing"].SetChecked(false)
		}
	})

	app.bypassCheckboxes["Process Mirroring"] = widget.NewCheck("进程镜像", func(checked bool) {
		app.processMirroring = checked
	})

	app.bypassCheckboxes["APC Queueing"] = widget.NewCheck("APC队列", func(checked bool) {
		app.apcQueueing = checked
	})

	app.bypassCheckboxes["Stealthy Threads"] = widget.NewCheck("隐蔽线程", func(checked bool) {
		app.stealthyThreads = checked
		if checked && app.threadHijacking {
			app.threadHijacking = false
			app.bypassCheckboxes["Thread Hijacking"].SetChecked(false)
		}
	})

	app.bypassCheckboxes["Randomize Allocation"] = widget.NewCheck("随机分配", func(checked bool) {
		app.randomizeAllocation = checked
	})

	app.bypassCheckboxes["Memory Fluctuation"] = widget.NewCheck("内存波动", func(checked bool) {
		app.memoryFluctuation = checked
	})

	app.bypassCheckboxes["Multi-Stage Injection"] = widget.NewCheck("多阶段", func(checked bool) {
		app.multiStageInjection = checked
	})

	app.bypassCheckboxes["Delayed Execution"] = widget.NewCheck("延迟执行", func(checked bool) {
		app.delayedExecution = checked
	})

	// 使用3列网格布局，紧凑排列所有选项
	return container.NewGridWithColumns(3,
		app.bypassCheckboxes["PTE Modification"],
		app.bypassCheckboxes["VAD Manipulation"],
		app.bypassCheckboxes["Remove VAD Node"],
		app.bypassCheckboxes["Direct Syscalls"],
		app.bypassCheckboxes["Allocate Behind Thread Stack"],
		app.bypassCheckboxes["Anti-Debug Techniques"],
		app.bypassCheckboxes["Anti-VM Techniques"],
		app.bypassCheckboxes["Process Hollowing"],
		app.bypassCheckboxes["Thread Hijacking"],
		app.bypassCheckboxes["Map to Hidden Memory"],
		app.bypassCheckboxes["Process Doppelganging"],
		app.bypassCheckboxes["Multi-Stage Injection"],
	)
}

// createUltraCompactPresetTab 创建超紧凑的预设标签页
func (app *Application) createUltraCompactPresetTab() fyne.CanvasObject {
	// 预设配置按钮 - 使用更紧凑的文字
	basicPresetBtn := widget.NewButton("🟢 基础", func() {
		app.applyBasicPreset()
	})
	basicPresetBtn.Importance = widget.MediumImportance

	advancedPresetBtn := widget.NewButton("🟡 高级", func() {
		app.applyAdvancedPreset()
	})
	advancedPresetBtn.Importance = widget.MediumImportance

	expertPresetBtn := widget.NewButton("🔴 专家", func() {
		app.applyExpertPreset()
	})
	expertPresetBtn.Importance = widget.MediumImportance

	clearAllBtn := widget.NewButton("🔄 清除", func() {
		app.clearAllOptions()
	})
	clearAllBtn.Importance = widget.LowImportance

	// 紧凑的说明文字
	infoLabel := widget.NewLabel("快速应用预设配置:")
	infoLabel.TextStyle = fyne.TextStyle{Bold: true}

	// 使用2x2网格布局
	buttonGrid := container.NewGridWithColumns(2,
		basicPresetBtn,
		advancedPresetBtn,
		expertPresetBtn,
		clearAllBtn,
	)

	return container.NewVBox(
		infoLabel,
		buttonGrid,
	)
}

// applyBasicPreset 应用基础预设配置
func (app *Application) applyBasicPreset() {
	app.clearAllOptions()

	// 基础隐蔽选项
	app.memoryLoad = true
	app.peHeaderErasure = true
	app.pathSpoofing = true

	// 更新UI
	app.updateCheckboxStates()
	app.updateBypassOptionsState()
}

// applyAdvancedPreset 应用高级预设配置
func (app *Application) applyAdvancedPreset() {
	app.clearAllOptions()

	// 包含基础选项
	app.memoryLoad = true
	app.peHeaderErasure = true
	app.pathSpoofing = true

	// 高级选项
	app.manualMapping = true
	app.invisibleMemory = true
	app.vadManipulation = true
	app.antiDebugTechniques = true
	app.directSyscalls = true

	// 更新UI
	app.updateCheckboxStates()
	app.updateBypassOptionsState()
}

// applyExpertPreset 应用专家预设配置
func (app *Application) applyExpertPreset() {
	app.clearAllOptions()

	// 包含高级选项
	app.memoryLoad = true
	app.peHeaderErasure = true
	app.entryPointErase = true
	app.manualMapping = true
	app.invisibleMemory = true
	app.vadManipulation = true
	app.removeVADNode = true
	app.antiDebugTechniques = true
	app.antiVMTechniques = true
	app.directSyscalls = true

	// 专家级选项
	app.processHollowing = true
	app.threadHijacking = true
	app.multiStageInjection = true
	app.randomizeAllocation = true
	app.memoryFluctuation = true
	app.delayedExecution = true

	// 更新UI
	app.updateCheckboxStates()
	app.updateBypassOptionsState()
}

// clearAllOptions 清除所有选项
func (app *Application) clearAllOptions() {
	// 重置所有布尔值
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
	app.antiDebugTechniques = false
	app.antiVMTechniques = false
	app.processHollowing = false
	app.doppelgangingProcess = false
	app.processMirroring = false
	app.threadHijacking = false
	app.apcQueueing = false
	app.stealthyThreads = false
	app.randomizeAllocation = false
	app.memoryFluctuation = false
	app.multiStageInjection = false
	app.delayedExecution = false

	// 更新UI
	app.updateCheckboxStates()
}

// updateCheckboxStates 更新所有checkbox的状态
func (app *Application) updateCheckboxStates() {
	checkboxMap := map[string]bool{
		"Load DLL from Memory":         app.memoryLoad,
		"Erase PE Header":              app.peHeaderErasure,
		"Erase Entry Point":            app.entryPointErase,
		"Use Manual Mapping":           app.manualMapping,
		"Map to Hidden Memory":         app.invisibleMemory,
		"Path Spoofing":                app.pathSpoofing,
		"Use Legitimate Process":       app.legitProcessInjection,
		"PTE Modification":             app.pteSpoofing,
		"VAD Manipulation":             app.vadManipulation,
		"Remove VAD Node":              app.removeVADNode,
		"Allocate Behind Thread Stack": app.allocBehindThreadStack,
		"Direct Syscalls":              app.directSyscalls,
		"Anti-Debug Techniques":        app.antiDebugTechniques,
		"Anti-VM Techniques":           app.antiVMTechniques,
		"Process Hollowing":            app.processHollowing,
		"Process Doppelganging":        app.doppelgangingProcess,
		"Process Mirroring":            app.processMirroring,
		"Thread Hijacking":             app.threadHijacking,
		"APC Queueing":                 app.apcQueueing,
		"Stealthy Threads":             app.stealthyThreads,
		"Randomize Allocation":         app.randomizeAllocation,
		"Memory Fluctuation":           app.memoryFluctuation,
		"Multi-Stage Injection":        app.multiStageInjection,
		"Delayed Execution":            app.delayedExecution,
	}

	for name, checked := range checkboxMap {
		if checkbox, exists := app.bypassCheckboxes[name]; exists {
			checkbox.SetChecked(checked)
		}
	}
}
