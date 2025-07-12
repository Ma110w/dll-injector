package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/whispin/dll-injector/internal/i18n"
)

func main() {
	fmt.Println("=== DLL Injector Internationalization Test ===")

	// Show system information
	fmt.Printf("OS: %s\n", runtime.GOOS)
	fmt.Printf("LANG: %s\n", os.Getenv("LANG"))
	fmt.Printf("LC_ALL: %s\n", os.Getenv("LC_ALL"))
	fmt.Printf("LC_MESSAGES: %s\n", os.Getenv("LC_MESSAGES"))
	fmt.Printf("LANGUAGE: %s\n", os.Getenv("LANGUAGE"))

	// Initialize i18n
	i18n.Init()

	// Show detected language
	currentLang := i18n.GetCurrentLanguage()
	fmt.Printf("Detected Language: %s\n", currentLang)

	fmt.Println("\n=== Testing Translations ===")

	// Test some key translations
	testKeys := []string{
		"app_title",
		"dll_file",
		"target_process",
		"injection_method",
		"inject",
		"console_logs",
		"standard_injection",
		"setwindowshookex",
		"queueuserapc",
		"early_bird",
		"dll_notification",
		"job_object",
		"anti_detection_options",
		"basic",
		"advanced",
		"preset",
		"memory_load",
		"manual_mapping",
		"erase_pe_header",
		"path_spoofing",
		"legitimate_process",
		"erase_entry_point",
		"dll_injector_starting",
		"dll_injector_started",
		"injection_successful",
		"injection_failed",
		"no_dll_selected",
		"no_process_selected_error",
		"please_select_dll",
		"please_select_process",
	}

	for _, key := range testKeys {
		translation := i18n.T(key)
		fmt.Printf("%-30s: %s\n", key, translation)
	}

	fmt.Println("\n=== Testing Language Switch ===")

	// Test switching to English
	fmt.Println("Switching to English...")
	i18n.SetLanguage(i18n.English)
	fmt.Printf("app_title (EN): %s\n", i18n.T("app_title"))
	fmt.Printf("dll_file (EN): %s\n", i18n.T("dll_file"))
	fmt.Printf("injection_method (EN): %s\n", i18n.T("injection_method"))

	// Test switching to Chinese
	fmt.Println("\nSwitching to Chinese...")
	i18n.SetLanguage(i18n.Chinese)
	fmt.Printf("app_title (ZH): %s\n", i18n.T("app_title"))
	fmt.Printf("dll_file (ZH): %s\n", i18n.T("dll_file"))
	fmt.Printf("injection_method (ZH): %s\n", i18n.T("injection_method"))

	// Test fallback behavior
	fmt.Println("\n=== Testing Fallback ===")
	nonExistentKey := "non_existent_key_12345"
	fallback := i18n.T(nonExistentKey)
	fmt.Printf("Non-existent key '%s' returns: '%s'\n", nonExistentKey, fallback)

	fmt.Println("\n=== Test Complete ===")
}
