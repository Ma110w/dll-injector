package injector

import (
	"fmt"
	"log"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Global debug flag
var DebugMode = false

// SetDebugMode enables or disables debug output
func SetDebugMode(enabled bool) {
	DebugMode = enabled
	if enabled {
		log.SetOutput(os.Stdout)
		log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	}
}

// SafeStringFromBytes safely converts bytes to string
func SafeStringFromBytes(data []byte, maxLen int) string {
	if len(data) == 0 {
		return ""
	}

	// Find null terminator
	nullIndex := -1
	for i, b := range data {
		if b == 0 {
			nullIndex = i
			break
		}
	}

	// Limit length to prevent excessive output
	if nullIndex == -1 {
		if len(data) > maxLen {
			return string(data[:maxLen]) + "..."
		}
		return string(data)
	}

	if nullIndex > maxLen {
		return string(data[:maxLen]) + "..."
	}
	return string(data[:nullIndex])
}

// ValidateProcessAccess checks if we can access the target process
func ValidateProcessAccess(processID uint32) error {
	if processID == 0 {
		return fmt.Errorf("invalid process ID: 0")
	}

	// Try to open process with minimal permissions first
	hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, processID)
	if err != nil {
		return fmt.Errorf("cannot access process %d: %v (try running as administrator)", processID, err)
	}
	defer windows.CloseHandle(hProcess)

	// Check if process is still running
	var exitCode uint32
	err = windows.GetExitCodeProcess(hProcess, &exitCode)
	if err != nil {
		return fmt.Errorf("failed to query process %d status: %v", processID, err)
	}

	if exitCode != 259 { // STILL_ACTIVE = 259
		return fmt.Errorf("process %d is not running (exit code: %d)", processID, exitCode)
	}

	return nil
}

// SecureCleanup ensures sensitive data is properly cleaned up
func SecureCleanup(data []byte) {
	if len(data) > 0 {
		// Zero out sensitive data
		for i := range data {
			data[i] = 0
		}
	}
}

// GetArchitectureString returns human-readable architecture string
func GetArchitectureString(machine uint16) string {
	switch machine {
	case IMAGE_FILE_MACHINE_I386:
		return "x86 (32-bit)"
	case IMAGE_FILE_MACHINE_AMD64:
		return "x64 (64-bit)"
	default:
		return fmt.Sprintf("Unknown (0x%04X)", machine)
	}
}

// IsValidPEFile performs basic PE file validation
func IsValidPEFile(data []byte) error {
	if len(data) < 64 {
		return fmt.Errorf("file too small to be a PE file (size: %d bytes)", len(data))
	}

	// Check DOS signature
	if data[0] != 'M' || data[1] != 'Z' {
		return fmt.Errorf("invalid DOS signature (expected 'MZ', got '%c%c')", data[0], data[1])
	}

	// Get PE offset
	peOffset := *(*uint32)(unsafe.Pointer(&data[60]))
	if peOffset >= uint32(len(data)) || peOffset < 64 {
		return fmt.Errorf("invalid PE offset: %d (file size: %d)", peOffset, len(data))
	}

	// Check PE signature
	if peOffset+4 > uint32(len(data)) {
		return fmt.Errorf("PE signature beyond file end")
	}

	if data[peOffset] != 'P' || data[peOffset+1] != 'E' || data[peOffset+2] != 0 || data[peOffset+3] != 0 {
		return fmt.Errorf("invalid PE signature")
	}

	return nil
}

// LogInjectionAttempt logs injection attempts for debugging
func LogInjectionAttempt(method string, processID uint32, dllPath string, success bool) {
	status := "SUCCESS"
	if !success {
		status = "FAILED"
	}

	if DebugMode {
		log.Printf("INJECTION ATTEMPT [%s]: Method=%s, PID=%d, DLL=%s\n",
			status, method, processID, dllPath)
	}
}

// IsProcess64Bit determines if a process is 64-bit
func IsProcess64Bit(processID uint32) (bool, error) {
	hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, processID)
	if err != nil {
		return false, fmt.Errorf("failed to open process: %v", err)
	}
	defer windows.CloseHandle(hProcess)

	var wow64Process bool
	err = windows.IsWow64Process(hProcess, &wow64Process)
	if err != nil {
		return false, fmt.Errorf("failed to check WOW64 process: %v", err)
	}

	// If it's a WOW64 process, it's 32-bit running on 64-bit
	// If it's not WOW64 and we're on 64-bit, it's native 64-bit
	// If it's not WOW64 and we're on 32-bit, it's native 32-bit
	if wow64Process {
		return false, nil // 32-bit process on 64-bit system
	}

	// Check if the current system is 64-bit
	if unsafe.Sizeof(uintptr(0)) == 8 {
		return true, nil // Native 64-bit process on 64-bit system
	}

	return false, nil // Native 32-bit process on 32-bit system
}

// ProcessInfo contains process creation information
type ProcessInfo struct {
	Process uint32
	Thread  uint32
}

// CreateSuspendedProcess creates a process in suspended state
func CreateSuspendedProcess(executablePath string) (*ProcessInfo, error) {
	if executablePath == "" {
		// Use notepad.exe as default target for process hollowing
		executablePath = "notepad.exe"
	}

	// Convert path to UTF16
	cmdLine, err := windows.UTF16PtrFromString(executablePath)
	if err != nil {
		return nil, fmt.Errorf("failed to convert path to UTF16: %v", err)
	}

	// Initialize startup info
	var si windows.StartupInfo
	var pi windows.ProcessInformation
	si.Cb = uint32(unsafe.Sizeof(si))

	// Create process in suspended state
	err = windows.CreateProcess(
		nil,                      // lpApplicationName
		cmdLine,                  // lpCommandLine
		nil,                      // lpProcessAttributes
		nil,                      // lpThreadAttributes
		false,                    // bInheritHandles
		windows.CREATE_SUSPENDED, // dwCreationFlags
		nil,                      // lpEnvironment
		nil,                      // lpCurrentDirectory
		&si,                      // lpStartupInfo
		&pi,                      // lpProcessInformation
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create suspended process: %v", err)
	}

	// Return process information
	processInfo := &ProcessInfo{
		Process: pi.ProcessId,
		Thread:  pi.ThreadId,
	}

	// Close handles as they're not needed for our use case
	windows.CloseHandle(pi.Process)
	windows.CloseHandle(pi.Thread)

	return processInfo, nil
}

// FindAlertableThread finds a thread that can be made alertable
func FindAlertableThread(processID uint32) (windows.Handle, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snapshot)

	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))

	err = windows.Thread32First(snapshot, &te)
	if err != nil {
		return 0, err
	}

	for {
		if te.OwnerProcessID == processID {
			// Try to open thread with required permissions
			threadHandle, err := windows.OpenThread(
				windows.THREAD_SET_CONTEXT|windows.THREAD_SUSPEND_RESUME|
					windows.THREAD_GET_CONTEXT|windows.THREAD_QUERY_INFORMATION,
				false, te.ThreadID)

			if err == nil {
				return threadHandle, nil
			}
		}

		err = windows.Thread32Next(snapshot, &te)
		if err != nil {
			break
		}
	}

	return 0, fmt.Errorf("no alertable thread found for process %d", processID)
}
