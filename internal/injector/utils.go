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

	// Get PE offset with bounds checking
	if len(data) < 64 {
		return fmt.Errorf("file too small for PE offset: %d bytes (need at least 64)", len(data))
	}
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

// ProcessArchitecture contains detailed process architecture information
type ProcessArchitecture struct {
	Is64Bit         bool
	IsWow64         bool
	MachineType     uint16
	SystemArch      string
	ProcessArch     string
	Compatible      bool
	InjectorArch    string
	Recommendations []string
}

// DetectProcessArchitecture performs comprehensive process architecture detection
func DetectProcessArchitecture(processID uint32) (*ProcessArchitecture, error) {
	arch := &ProcessArchitecture{
		Recommendations: make([]string, 0),
	}

	// Open process for querying
	hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, processID)
	if err != nil {
		return nil, fmt.Errorf("failed to open process for architecture detection: %v", err)
	}
	defer windows.CloseHandle(hProcess)

	// Detect WOW64 status
	var wow64Process bool
	err = windows.IsWow64Process(hProcess, &wow64Process)
	if err != nil {
		return nil, fmt.Errorf("failed to check WOW64 process: %v", err)
	}
	arch.IsWow64 = wow64Process

	// Determine system architecture
	if unsafe.Sizeof(uintptr(0)) == 8 {
		arch.SystemArch = "x64"
		arch.InjectorArch = "x64"
	} else {
		arch.SystemArch = "x86"
		arch.InjectorArch = "x86"
	}

	// Determine process architecture
	if wow64Process {
		// 32-bit process running on 64-bit system
		arch.Is64Bit = false
		arch.ProcessArch = "x86"
		arch.MachineType = IMAGE_FILE_MACHINE_I386
	} else {
		if arch.SystemArch == "x64" {
			// Native 64-bit process on 64-bit system
			arch.Is64Bit = true
			arch.ProcessArch = "x64"
			arch.MachineType = IMAGE_FILE_MACHINE_AMD64
		} else {
			// Native 32-bit process on 32-bit system
			arch.Is64Bit = false
			arch.ProcessArch = "x86"
			arch.MachineType = IMAGE_FILE_MACHINE_I386
		}
	}

	// Determine compatibility
	arch.Compatible = (arch.ProcessArch == arch.InjectorArch)

	// Generate recommendations
	arch.generateRecommendations()

	return arch, nil
}

// generateRecommendations generates architecture-specific recommendations
func (arch *ProcessArchitecture) generateRecommendations() {
	if !arch.Compatible {
		if arch.ProcessArch == "x86" && arch.InjectorArch == "x64" {
			arch.Recommendations = append(arch.Recommendations,
				"Target process is 32-bit but injector is 64-bit - this will fail")
			arch.Recommendations = append(arch.Recommendations,
				"Use a 32-bit version of the injector or target a 64-bit process")
		} else if arch.ProcessArch == "x64" && arch.InjectorArch == "x86" {
			arch.Recommendations = append(arch.Recommendations,
				"Target process is 64-bit but injector is 32-bit - this will fail")
			arch.Recommendations = append(arch.Recommendations,
				"Use a 64-bit version of the injector or target a 32-bit process")
		}
	} else {
		arch.Recommendations = append(arch.Recommendations,
			"Process and injector architectures are compatible")
	}

	if arch.IsWow64 {
		arch.Recommendations = append(arch.Recommendations,
			"Target is a WOW64 process (32-bit on 64-bit system)")
		arch.Recommendations = append(arch.Recommendations,
			"Some injection methods may have additional compatibility considerations")
	}
}

// ValidateDLLCompatibility checks if a DLL is compatible with the target process
func ValidateDLLCompatibility(processID uint32, dllBytes []byte) (*ArchitectureCompatibility, error) {
	compat := &ArchitectureCompatibility{}

	// Detect process architecture
	processArch, err := DetectProcessArchitecture(processID)
	if err != nil {
		return nil, fmt.Errorf("failed to detect process architecture: %v", err)
	}
	compat.ProcessArch = processArch

	// Parse DLL architecture
	dllArch, err := DetectDLLArchitecture(dllBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to detect DLL architecture: %v", err)
	}
	compat.DLLArch = dllArch

	// Check compatibility
	compat.Compatible = (processArch.MachineType == dllArch.MachineType)
	compat.generateCompatibilityRecommendations()

	return compat, nil
}

// ArchitectureCompatibility contains compatibility analysis
type ArchitectureCompatibility struct {
	ProcessArch     *ProcessArchitecture
	DLLArch         *DLLArchitecture
	Compatible      bool
	Recommendations []string
}

// DLLArchitecture contains DLL architecture information
type DLLArchitecture struct {
	Is64Bit      bool
	MachineType  uint16
	Architecture string
	IsValidPE    bool
	Subsystem    uint16
}

// DetectDLLArchitecture analyzes DLL architecture from bytes
func DetectDLLArchitecture(dllBytes []byte) (*DLLArchitecture, error) {
	arch := &DLLArchitecture{}

	// Validate PE file first
	if err := IsValidPEFile(dllBytes); err != nil {
		arch.IsValidPE = false
		return nil, fmt.Errorf("invalid PE file: %v", err)
	}
	arch.IsValidPE = true

	// Get PE offset
	if len(dllBytes) < 64 {
		return nil, fmt.Errorf("file too small for PE analysis")
	}
	peOffset := *(*uint32)(unsafe.Pointer(&dllBytes[60]))

	// Get machine type from COFF header
	if peOffset+24 > uint32(len(dllBytes)) {
		return nil, fmt.Errorf("COFF header out of bounds")
	}
	machineOffset := peOffset + 4 // PE signature (4 bytes) + machine type offset
	arch.MachineType = *(*uint16)(unsafe.Pointer(&dllBytes[machineOffset]))

	// Determine architecture
	switch arch.MachineType {
	case IMAGE_FILE_MACHINE_I386:
		arch.Is64Bit = false
		arch.Architecture = "x86"
	case IMAGE_FILE_MACHINE_AMD64:
		arch.Is64Bit = true
		arch.Architecture = "x64"
	default:
		return nil, fmt.Errorf("unsupported machine type: 0x%04X", arch.MachineType)
	}

	// Get subsystem if available
	if peOffset+68 < uint32(len(dllBytes)) {
		arch.Subsystem = *(*uint16)(unsafe.Pointer(&dllBytes[peOffset+68]))
	}

	return arch, nil
}

// generateCompatibilityRecommendations generates compatibility recommendations
func (compat *ArchitectureCompatibility) generateCompatibilityRecommendations() {
	compat.Recommendations = make([]string, 0)

	if !compat.Compatible {
		compat.Recommendations = append(compat.Recommendations,
			fmt.Sprintf("Architecture mismatch: Process is %s but DLL is %s",
				compat.ProcessArch.ProcessArch, compat.DLLArch.Architecture))

		if compat.DLLArch.Architecture == "x64" && compat.ProcessArch.ProcessArch == "x86" {
			compat.Recommendations = append(compat.Recommendations,
				"Cannot inject 64-bit DLL into 32-bit process")
			compat.Recommendations = append(compat.Recommendations,
				"Solution: Use a 32-bit version of the DLL or target a 64-bit process")
		} else if compat.DLLArch.Architecture == "x86" && compat.ProcessArch.ProcessArch == "x64" {
			compat.Recommendations = append(compat.Recommendations,
				"Cannot inject 32-bit DLL into 64-bit process")
			compat.Recommendations = append(compat.Recommendations,
				"Solution: Use a 64-bit version of the DLL or target a 32-bit process")
		}
	} else {
		compat.Recommendations = append(compat.Recommendations,
			"DLL and process architectures are compatible")

		if compat.ProcessArch.IsWow64 {
			compat.Recommendations = append(compat.Recommendations,
				"Target is WOW64 - ensure DLL dependencies are also 32-bit")
		}
	}
}

// IsProcess64Bit determines if a process is 64-bit (legacy compatibility function)
func IsProcess64Bit(processID uint32) (bool, error) {
	arch, err := DetectProcessArchitecture(processID)
	if err != nil {
		return false, err
	}
	return arch.Is64Bit, nil
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
