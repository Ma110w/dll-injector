package i18n

import (
	"os"
	"runtime"
	"strings"
)

// Language represents supported languages
type Language string

const (
	English Language = "en"
	Chinese Language = "zh"
)

// Localizer handles internationalization
type Localizer struct {
	currentLang  Language
	translations map[Language]map[string]string
}

// NewLocalizer creates a new localizer instance
func NewLocalizer() *Localizer {
	l := &Localizer{
		translations: make(map[Language]map[string]string),
	}

	// Initialize translations
	l.initTranslations()

	// Detect system language
	l.currentLang = l.detectSystemLanguage()

	return l
}

// detectSystemLanguage detects the system language
func (l *Localizer) detectSystemLanguage() Language {
	// Check environment variables
	lang := os.Getenv("LANG")
	if lang == "" {
		lang = os.Getenv("LC_ALL")
	}
	if lang == "" {
		lang = os.Getenv("LC_MESSAGES")
	}

	// On Windows, check additional environment variables
	if runtime.GOOS == "windows" {
		if lang == "" {
			lang = os.Getenv("LANGUAGE")
		}
	}

	// Convert to lowercase for comparison
	lang = strings.ToLower(lang)

	// Check if it's Chinese
	if strings.Contains(lang, "zh") ||
		strings.Contains(lang, "chinese") ||
		strings.Contains(lang, "cn") {
		return Chinese
	}

	// Default to English
	return English
}

// T translates a key to the current language
func (l *Localizer) T(key string) string {
	if translations, exists := l.translations[l.currentLang]; exists {
		if translation, exists := translations[key]; exists {
			return translation
		}
	}

	// Fallback to English
	if l.currentLang != English {
		if translations, exists := l.translations[English]; exists {
			if translation, exists := translations[key]; exists {
				return translation
			}
		}
	}

	// Return key if no translation found
	return key
}

// SetLanguage sets the current language
func (l *Localizer) SetLanguage(lang Language) {
	l.currentLang = lang
}

// GetCurrentLanguage returns the current language
func (l *Localizer) GetCurrentLanguage() Language {
	return l.currentLang
}

// initTranslations initializes all translations
func (l *Localizer) initTranslations() {
	// English translations
	l.translations[English] = map[string]string{
		// Window and UI
		"app_title":              "DLL Injector",
		"dll_file":               "DLL File:",
		"target_process":         "Target Process:",
		"injection_method":       "Injection Method:",
		"anti_detection_options": "Anti-Detection Options",
		"select_dll_placeholder": "Select DLL file path...",
		"select_process":         "Select Process",
		"no_process_selected":    "No Process Selected",
		"inject":                 "Inject",
		"console_logs":           "Console Logs",

		// Injection Methods
		"standard_injection": "Standard Injection",
		"setwindowshookex":   "SetWindowsHookEx",
		"queueuserapc":       "QueueUserAPC",
		"early_bird":         "Early Bird",
		"dll_notification":   "DLL Notification",
		"job_object":         "Job Object",

		// Anti-Detection Options - Tabs
		"basic":    "Basic",
		"advanced": "Advanced",
		"preset":   "Preset",

		// Basic Options
		"memory_load":        "Memory Load",
		"manual_mapping":     "Manual Mapping",
		"erase_pe_header":    "Erase PE Header",
		"path_spoofing":      "Path Spoofing",
		"legitimate_process": "Legitimate Process",
		"erase_entry_point":  "Erase Entry Point",

		// Advanced Options
		"pte_modification":        "PTE Modification",
		"vad_manipulation":        "VAD Manipulation",
		"remove_vad_node":         "Remove VAD Node",
		"direct_syscalls":         "Direct Syscalls",
		"thread_stack_allocation": "Thread Stack Allocation",
		"anti_debug":              "Anti-Debug",
		"anti_vm":                 "Anti-VM",
		"process_hollowing":       "Process Hollowing",
		"thread_hijacking":        "Thread Hijacking",
		"hidden_memory":           "Hidden Memory",
		"process_doppelganging":   "Process Doppelganging",
		"multi_stage_injection":   "Multi-Stage Injection",

		// Preset Options
		"preset_info":      "Quick apply preset configurations:",
		"basic_stealth":    "Basic",
		"advanced_stealth": "Advanced",
		"expert_stealth":   "Expert",
		"clear_all":        "Clear",

		// Messages and Logs
		"dll_injector_starting":      "DLL Injector starting",
		"dll_injector_started":       "DLL Injector started",
		"injection_method_selected":  "Injection method selected",
		"process_selected":           "Process selected",
		"starting_dll_injection":     "Starting DLL injection",
		"injection_successful":       "Injection successful",
		"injection_failed":           "Injection failed",
		"no_dll_selected":            "No DLL file selected",
		"no_process_selected_error":  "No target process selected",
		"please_select_dll":          "Please select a DLL file",
		"please_select_process":      "Please select a target process",
		"injection_successful_title": "Injection Successful",
		"injection_successful_msg":   "DLL has been successfully injected into the target process",

		// Process Dialog
		"select_target_process": "Select Target Process",
		"close":                 "Close",
		"refresh":               "Refresh",
		"process_name":          "Process Name",
		"pid":                   "PID",
		"path":                  "Path",
	}

	// Chinese translations
	l.translations[Chinese] = map[string]string{
		// Window and UI
		"app_title":              "DLL注入器",
		"dll_file":               "DLL文件:",
		"target_process":         "目标进程:",
		"injection_method":       "注入方式:",
		"anti_detection_options": "反检测选项",
		"select_dll_placeholder": "选择DLL文件路径...",
		"select_process":         "选择进程",
		"no_process_selected":    "未选择进程",
		"inject":                 "注入",
		"console_logs":           "控制台日志",

		// Injection Methods
		"standard_injection": "标准注入",
		"setwindowshookex":   "钩子注入",
		"queueuserapc":       "APC注入",
		"early_bird":         "早鸟注入",
		"dll_notification":   "DLL通知",
		"job_object":         "作业对象",

		// Anti-Detection Options - Tabs
		"basic":    "基础",
		"advanced": "高级",
		"preset":   "预设",

		// Basic Options
		"memory_load":        "内存加载",
		"manual_mapping":     "手动映射",
		"erase_pe_header":    "擦除PE头",
		"path_spoofing":      "路径伪装",
		"legitimate_process": "合法进程",
		"erase_entry_point":  "擦除入口",

		// Advanced Options
		"pte_modification":        "PTE修改",
		"vad_manipulation":        "VAD操作",
		"remove_vad_node":         "移除VAD",
		"direct_syscalls":         "直接调用",
		"thread_stack_allocation": "线程栈",
		"anti_debug":              "反调试",
		"anti_vm":                 "反虚拟机",
		"process_hollowing":       "进程挖空",
		"thread_hijacking":        "线程劫持",
		"hidden_memory":           "隐藏内存",
		"process_doppelganging":   "进程替身",
		"multi_stage_injection":   "多阶段",

		// Preset Options
		"preset_info":      "快速应用预设配置:",
		"basic_stealth":    "基础",
		"advanced_stealth": "高级",
		"expert_stealth":   "专家",
		"clear_all":        "清除",

		// Messages and Logs
		"dll_injector_starting":      "DLL注入器启动中",
		"dll_injector_started":       "DLL注入器已启动",
		"injection_method_selected":  "选择注入方式",
		"process_selected":           "选择目标进程",
		"starting_dll_injection":     "开始注入",
		"injection_successful":       "注入成功完成",
		"injection_failed":           "注入失败",
		"no_dll_selected":            "未选择DLL文件",
		"no_process_selected_error":  "未选择目标进程",
		"please_select_dll":          "请选择一个DLL文件",
		"please_select_process":      "请选择一个目标进程",
		"injection_successful_title": "注入成功",
		"injection_successful_msg":   "DLL已成功注入到目标进程",

		// Process Dialog
		"select_target_process": "选择目标进程",
		"close":                 "关闭",
		"refresh":               "刷新",
		"process_name":          "进程名称",
		"pid":                   "进程ID",
		"path":                  "路径",
	}
}

// Global localizer instance
var globalLocalizer *Localizer

// Init initializes the global localizer
func Init() {
	globalLocalizer = NewLocalizer()
}

// T is a convenience function for translation
func T(key string) string {
	if globalLocalizer == nil {
		Init()
	}
	return globalLocalizer.T(key)
}

// SetLanguage sets the global language
func SetLanguage(lang Language) {
	if globalLocalizer == nil {
		Init()
	}
	globalLocalizer.SetLanguage(lang)
}

// GetCurrentLanguage returns the current global language
func GetCurrentLanguage() Language {
	if globalLocalizer == nil {
		Init()
	}
	return globalLocalizer.GetCurrentLanguage()
}
