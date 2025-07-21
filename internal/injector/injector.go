package injector

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// InjectionMethod defines different injection methods
type InjectionMethod int

const (
	StandardInjection InjectionMethod = iota
	SetWindowsHookExInjection
	QueueUserAPCInjection
	EarlyBirdAPCInjection
	DllNotificationInjection
	CryoBirdInjection
)

// BypassOptions defines anti-detection options
type BypassOptions struct {
	MemoryLoad            bool
	ErasePEHeader         bool
	EraseEntryPoint       bool
	ManualMapping         bool
	InvisibleMemory       bool
	PathSpoofing          bool
	LegitProcessInjection bool
	PTESpoofing           bool
	VADManipulation       bool
	RemoveVADNode         bool
	ThreadStackAllocation bool
	DirectSyscalls        bool
	SkipDllMain           bool // Skip DllMain execution for problematic DLLs
}

// Injector represents a DLL injector instance
type Injector struct {
	dllPath            string
	processID          uint32
	method             InjectionMethod
	bypassOptions      BypassOptions
	enhancedOptions    EnhancedBypassOptions
	useEnhancedOptions bool
	logger             Logger
}

// Configuration constants for consistent timeouts
const (
	DefaultTimeoutShort  = 5 * time.Second  // For quick operations
	DefaultTimeoutMedium = 10 * time.Second // For normal operations
	DefaultTimeoutLong   = 15 * time.Second // For complex operations
)

// NewInjector creates a new injector instance
func NewInjector(dllPath string, processID uint32, logger Logger) *Injector {
	return &Injector{
		dllPath:   dllPath,
		processID: processID,
		method:    StandardInjection,
		logger:    logger,
	}
}

// SetMethod sets the injection method
func (i *Injector) SetMethod(method InjectionMethod) {
	i.method = method
}

// SetBypassOptions sets anti-detection options with compatibility validation
func (i *Injector) SetBypassOptions(options BypassOptions) {
	// Validate compatibility between injection method and bypass options
	i.validateBypassCompatibility(&options)
	i.bypassOptions = options
	i.useEnhancedOptions = false
}

// validateBypassCompatibility checks if bypass options are compatible with injection method
func (i *Injector) validateBypassCompatibility(options *BypassOptions) {
	// Check if using safe methods (Memory Load or Manual Mapping)
	usingSafeMethods := options.MemoryLoad || options.ManualMapping

	// Check PE header erasure compatibility
	if options.ErasePEHeader {
		if usingSafeMethods {
			// Safe combination - no warnings needed
			i.logger.Debug("PE header erasure enabled with safe injection method")
		} else {
			switch i.method {
			case StandardInjection, QueueUserAPCInjection, EarlyBirdAPCInjection:
				i.logger.Warn("PE header erasure may cause issues with LoadLibrary-based injection methods")
				i.logger.Warn("Consider using Memory Load or Manual Mapping for safer PE header erasure")

			case SetWindowsHookExInjection:
				i.logger.Error("PE header erasure is incompatible with SetWindowsHookEx injection")
				i.logger.Error("Disabling PE header erasure for SetWindowsHookEx method")
				options.ErasePEHeader = false

			case DllNotificationInjection:
				i.logger.Error("PE header erasure is incompatible with DLL notification injection")
				i.logger.Error("Disabling PE header erasure for DLL notification method")
				options.ErasePEHeader = false
			}
		}
	}

	// Check entry point erasure compatibility
	if options.EraseEntryPoint {
		if usingSafeMethods {
			// Safe combination - no warnings needed
			i.logger.Debug("Entry point erasure enabled with safe injection method")
		} else {
			switch i.method {
			case StandardInjection, QueueUserAPCInjection, EarlyBirdAPCInjection:
				i.logger.Warn("Entry point erasure may cause DLL functionality issues with LoadLibrary-based methods")
				i.logger.Warn("Consider using Memory Load or Manual Mapping for safer entry point erasure")

			case SetWindowsHookExInjection:
				i.logger.Error("Entry point erasure may break hook functionality")
				i.logger.Error("Disabling entry point erasure for SetWindowsHookEx method")
				options.EraseEntryPoint = false
			}
		}
	}

	// Provide recommendations for optimal combinations
	if (options.ErasePEHeader || options.EraseEntryPoint) && !usingSafeMethods {
		i.logger.Info("Recommendation: Enable Memory Load or Manual Mapping for safer PE/entry point erasure")
	}
}

// SetEnhancedBypassOptions sets enhanced anti-detection options
func (i *Injector) SetEnhancedBypassOptions(options EnhancedBypassOptions) {
	i.enhancedOptions = options
	i.useEnhancedOptions = true
}

// validateConfiguration performs comprehensive parameter validation
func (i *Injector) validateConfiguration() error {
	if i.logger == nil {
		return fmt.Errorf("logger not initialized")
	}

	// Validate inputs
	if i.dllPath == "" {
		i.logger.Error("DLL path is empty")
		return fmt.Errorf("DLL path cannot be empty")
	}

	if i.processID == 0 {
		i.logger.Error("Process ID is invalid")
		return fmt.Errorf("process ID cannot be 0")
	}

	// Validate method compatibility
	if i.method < 0 || int(i.method) > 5 {
		return fmt.Errorf("invalid injection method: %d", i.method)
	}

	return nil
}

// Inject performs DLL injection using the configured method
func (i *Injector) Inject() error {
	// Comprehensive validation before injection
	if err := i.validateConfiguration(); err != nil {
		return fmt.Errorf("configuration validation failed: %v", err)
	}

	// Additional process access validation
	if err := ValidateProcessAccess(i.processID); err != nil {
		i.logger.Error("Process access validation failed", "error", err)
		return err
	}

	// Check if DLL file exists and get detailed info
	fileInfo, err := os.Stat(i.dllPath)
	if os.IsNotExist(err) {
		i.logger.Error("DLL file does not exist", "path", i.dllPath)
		return fmt.Errorf("DLL file does not exist: %s", i.dllPath)
	}
	i.logger.Info("DLL file found", "path", i.dllPath, "size", fileInfo.Size())

	// Read and validate DLL file
	dllBytes, err := os.ReadFile(i.dllPath)
	if err != nil {
		i.logger.Error("Failed to read DLL file", "error", err)
		return fmt.Errorf("failed to read DLL file: %v", err)
	}

	// Validate PE file format
	if err := IsValidPEFile(dllBytes); err != nil {
		i.logger.Error("Invalid PE file", "error", err)
		return fmt.Errorf("invalid PE file: %v", err)
	}

	// Enhanced automatic architecture detection and validation
	i.logger.Info("Performing comprehensive architecture analysis")
	archCompat, err := ValidateDLLCompatibility(i.processID, dllBytes)
	if err != nil {
		i.logger.Error("Architecture compatibility check failed", "error", err)
		return fmt.Errorf("architecture compatibility check failed: %v", err)
	}

	// Log detailed architecture information
	i.logger.Info("Architecture analysis completed",
		"process_arch", archCompat.ProcessArch.ProcessArch,
		"dll_arch", archCompat.DLLArch.Architecture,
		"compatible", archCompat.Compatible,
		"is_wow64", archCompat.ProcessArch.IsWow64)

	// Handle architecture incompatibility with automatic recommendations
	if !archCompat.Compatible {
		i.logger.Error("Architecture mismatch detected")
		for _, recommendation := range archCompat.Recommendations {
			i.logger.Error("Recommendation", "suggestion", recommendation)
		}
		return fmt.Errorf("architecture mismatch: %s",
			archCompat.Recommendations[0]) // Return first recommendation as error
	}

	// Log compatibility confirmation and any special considerations
	for _, recommendation := range archCompat.Recommendations {
		i.logger.Info("Architecture analysis", "note", recommendation)
	}

	// Apply architecture-specific optimizations to injection strategies
	if archCompat.ProcessArch.IsWow64 {
		i.logger.Info("WOW64 process detected - applying WOW64-specific optimizations")
		// For WOW64 processes, certain injection methods work better
		if i.method == SetWindowsHookExInjection {
			i.logger.Info("SetWindowsHookEx recommended for WOW64 processes")
		}
	}

	// Check and handle DLL signature
	signedDllBytes, err := i.handleDLLSignature(dllBytes)
	if err != nil {
		i.logger.Warn("Signature processing failed", "error", err)
		// Continue with original DLL if signature handling fails
		signedDllBytes = dllBytes
	} else {
		// Use the signed DLL bytes for injection
		dllBytes = signedDllBytes
	}

	// For disk-based injection methods, save signed DLL to temporary file
	var tempSignedPath string
	if !i.bypassOptions.MemoryLoad && !i.bypassOptions.ManualMapping {
		// Check if we need to use disk-based injection
		needsDiskFile := i.method == StandardInjection ||
			i.method == SetWindowsHookExInjection ||
			i.bypassOptions.PathSpoofing

		if needsDiskFile && len(signedDllBytes) != len(dllBytes) {
			// DLL was modified with signature, save to temp file
			tempSignedPath, err = i.saveTempSignedDLL(signedDllBytes)
			if err != nil {
				i.logger.Warn("Failed to save temporary signed file", "error", err)
			} else {
				// Update DLL path to use signed version
				originalPath := i.dllPath
				i.dllPath = tempSignedPath
				defer func() {
					// Clean up temporary file
					os.Remove(tempSignedPath)
					i.dllPath = originalPath // Restore original path
				}()
			}
		}
	}

	i.logger.Info("Starting injection with auto-recovery", "method", methodToString(i.method), "dll", i.dllPath, "pid", i.processID)

	// Log injection attempt
	LogInjectionAttempt(methodToString(i.method), i.processID, i.dllPath, false)

	// Attempt injection with automatic recovery
	injectionErr := i.attemptInjectionWithRecovery(dllBytes)

	// Log injection result
	LogInjectionAttempt(methodToString(i.method), i.processID, i.dllPath, injectionErr == nil)

	// Clean up sensitive data
	SecureCleanup(dllBytes)

	if injectionErr != nil {
		i.logger.Error("Injection failed", "error", injectionErr)
		return injectionErr
	}

	i.logger.Info("Injection completed successfully")
	return nil
}

// createTempDllFile creates a temporary file with DLL data using real DLL names
func (i *Injector) createTempDllFile(dllBytes []byte) (string, error) {
	tempDir := os.TempDir()

	// Use real system DLL names for better stealth
	realDllNames := []string{
		"msvcr120.dll",
		"msvcp120.dll",
		"vcruntime140.dll",
		"msvcp140.dll",
		"ucrtbase.dll",
		"concrt140.dll",
		"vccorlib140.dll",
		"api-ms-win-core-heap-l1-1-0.dll",
		"api-ms-win-core-synch-l1-2-0.dll",
		"api-ms-win-core-memory-l1-1-1.dll",
	}

	// Select a real DLL name based on process ID
	fileName := realDllNames[i.processID%uint32(len(realDllNames))]
	tempFile := filepath.Join(tempDir, fileName)

	err := os.WriteFile(tempFile, dllBytes, 0644)
	if err != nil {
		return "", fmt.Errorf("failed to create temporary DLL file: %v", err)
	}

	return tempFile, nil
}

// findLoadedDLLBaseAddress finds the base address of a loaded DLL in the target process
func (i *Injector) findLoadedDLLBaseAddress(hProcess windows.Handle, dllPath string) (uintptr, error) {
	// Get the DLL filename from the full path
	dllName := filepath.Base(dllPath)

	// Enumerate modules in the target process
	var moduleHandle windows.Handle
	var cbNeeded uint32
	var modules [1024]windows.Handle

	psapi := windows.NewLazySystemDLL("psapi.dll")
	enumProcessModules := psapi.NewProc("EnumProcessModules")
	getModuleBaseNameW := psapi.NewProc("GetModuleBaseNameW")
	getModuleInformation := psapi.NewProc("GetModuleInformation")

	ret, _, _ := enumProcessModules.Call(
		uintptr(hProcess),
		uintptr(unsafe.Pointer(&modules[0])),
		uintptr(len(modules)*int(unsafe.Sizeof(moduleHandle))),
		uintptr(unsafe.Pointer(&cbNeeded)))

	if ret == 0 {
		return 0, fmt.Errorf("failed to enumerate process modules")
	}

	moduleCount := cbNeeded / uint32(unsafe.Sizeof(moduleHandle))

	for i := uint32(0); i < moduleCount; i++ {
		var moduleInfo struct {
			BaseOfDll   uintptr
			SizeOfImage uint32
			EntryPoint  uintptr
		}

		// Get module information
		ret, _, _ := getModuleInformation.Call(
			uintptr(hProcess),
			uintptr(modules[i]),
			uintptr(unsafe.Pointer(&moduleInfo)),
			unsafe.Sizeof(moduleInfo))

		if ret == 0 {
			continue
		}

		// Get module name
		var moduleName [260]uint16
		ret, _, _ = getModuleBaseNameW.Call(
			uintptr(hProcess),
			uintptr(modules[i]),
			uintptr(unsafe.Pointer(&moduleName[0])),
			uintptr(len(moduleName)))

		if ret == 0 {
			continue
		}

		// Convert to string and compare
		moduleNameStr := windows.UTF16ToString(moduleName[:])
		if strings.EqualFold(moduleNameStr, dllName) {
			return moduleInfo.BaseOfDll, nil
		}
	}

	return 0, fmt.Errorf("DLL not found in process modules: %s", dllName)
}

// manualMapDLL implements manual DLL mapping
func (i *Injector) manualMapDLL(dllBytes []byte) error {
	i.logger.Info("Using advanced manual mapping method")

	// Open target process
	hProcess, err := windows.OpenProcess(
		windows.PROCESS_CREATE_THREAD|
			windows.PROCESS_VM_OPERATION|
			windows.PROCESS_VM_WRITE|
			windows.PROCESS_VM_READ|
			windows.PROCESS_QUERY_INFORMATION,
		false, i.processID)
	if err != nil {
		i.logger.Error("Failed to open target process", "error", err)
		return fmt.Errorf("failed to open target process: %v", err)
	}
	defer windows.CloseHandle(hProcess)

	// Use advanced manual mapping with comprehensive anti-detection
	baseAddress, err := i.AdvancedManualMapping(hProcess, dllBytes)
	if err != nil {
		i.logger.Error("Advanced manual mapping failed", "error", err)
		return fmt.Errorf("advanced manual mapping failed: %v", err)
	}

	i.logger.Info("Advanced manual mapping successful", "base_address", fmt.Sprintf("0x%X", baseAddress))

	// Apply enhanced techniques if configured
	if i.useEnhancedOptions {
		err = i.applyEnhancedInjectionTechniques(hProcess, baseAddress, uintptr(len(dllBytes)), dllBytes)
		if err != nil {
			i.logger.Warn("Enhanced techniques failed", "error", err)
		}
	}

	return nil
}

// manualMapDLLWithOptions implements manual DLL mapping with bypass options
func (i *Injector) manualMapDLLWithOptions(hProcess windows.Handle, dllBytes []byte) (uintptr, error) {
	i.logger.Info("Starting manual mapping with bypass options")

	// Parse PE header
	peHeader, err := ParsePEHeader(dllBytes)
	if err != nil {
		return 0, fmt.Errorf("failed to parse PE header: %v", err)
	}

	imageSize := peHeader.GetSizeOfImage()
	i.logger.Info("PE image size", "size", imageSize)

	var baseAddress uintptr

	// Use invisible memory allocation if enabled
	if i.bypassOptions.InvisibleMemory {
		i.logger.Info("Using invisible memory allocation")
		baseAddress, err = InvisibleMemoryAllocation(hProcess, uintptr(imageSize))
		if err != nil {
			return 0, fmt.Errorf("invisible memory allocation failed: %v", err)
		}
	} else {
		// Standard memory allocation
		baseAddress, err = VirtualAllocEx(hProcess, 0, uintptr(imageSize),
			windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_EXECUTE_READWRITE)
		if err != nil {
			return 0, fmt.Errorf("failed to allocate memory: %v", err)
		}
	}

	i.logger.Info("Memory allocated", "address", fmt.Sprintf("0x%X", baseAddress))

	// Map PE sections
	err = i.MapSections(hProcess, dllBytes, baseAddress, peHeader)
	if err != nil {
		return 0, fmt.Errorf("failed to map PE sections: %v", err)
	}

	// Process relocations
	err = FixRelocations(hProcess, baseAddress, peHeader)
	if err != nil {
		i.logger.Warn("Failed to process relocations", "error", err)
		// Continue anyway as some DLLs might work without relocations
	}

	// Resolve imports
	err = FixImports(hProcess, baseAddress, peHeader)
	if err != nil {
		i.logger.Warn("Failed to resolve imports", "error", err)
		// Continue anyway
	}

	// Execute DLL entry point if present
	err = ExecuteDllEntry(hProcess, baseAddress, peHeader)
	if err != nil {
		i.logger.Warn("Failed to execute DLL entry point", "error", err)
		// Continue anyway
	}

	return baseAddress, nil
}

// legitProcessInject performs injection through legitimate process
func (i *Injector) legitProcessInject(dllBytes []byte) error {
	i.logger.Info("Using legitimate process injection")

	// Open target process
	hProcess, err := windows.OpenProcess(
		windows.PROCESS_CREATE_THREAD|
			windows.PROCESS_VM_OPERATION|
			windows.PROCESS_VM_WRITE|
			windows.PROCESS_VM_READ|
			windows.PROCESS_QUERY_INFORMATION,
		false, i.processID)
	if err != nil {
		i.logger.Error("Failed to open target process", "error", err)
		return fmt.Errorf("failed to open target process: %v", err)
	}
	defer windows.CloseHandle(hProcess)

	// Create a legitimate process and inject through it
	err = LegitimateProcessInjection(hProcess, dllBytes)
	if err != nil {
		i.logger.Error("Legitimate process injection failed", "error", err)
		return fmt.Errorf("legitimate process injection failed: %v", err)
	}

	i.logger.Info("Legitimate process injection successful")
	return nil
}

// standardInject implements standard CreateRemoteThread injection
func (i *Injector) standardInject() error {
	i.logger.Info("Using standard injection method", "dll", i.dllPath, "pid", i.processID)

	// Open target process with all required permissions
	hProcess, err := windows.OpenProcess(
		windows.PROCESS_CREATE_THREAD|
			windows.PROCESS_VM_OPERATION|
			windows.PROCESS_VM_WRITE|
			windows.PROCESS_VM_READ|
			windows.PROCESS_QUERY_INFORMATION,
		false, i.processID)
	if err != nil {
		i.logger.Error("Failed to open target process", "error", err, "pid", i.processID)
		// Provide helpful error message based on common issues
		if err.Error() == "Access is denied." {
			return fmt.Errorf("access denied - target process may be protected or require elevated privileges (WARNING: only use elevated privileges for legitimate testing)")
		}
		return fmt.Errorf("failed to open target process: %v", err)
	}
	defer windows.CloseHandle(hProcess)
	i.logger.Info("Successfully opened target process", "handle", hProcess)

	// Verify process is still running
	var exitCode uint32
	err = windows.GetExitCodeProcess(hProcess, &exitCode)
	if err == nil && exitCode != 259 { // STILL_ACTIVE = 259
		i.logger.Error("Target process is not running", "exit_code", exitCode)
		return fmt.Errorf("target process has exited with code %d", exitCode)
	}

	// Convert DLL path to absolute path to avoid path resolution issues
	absPath, err := filepath.Abs(i.dllPath)
	if err != nil {
		i.logger.Warn("Failed to get absolute path", "error", err)
		absPath = i.dllPath
	}
	i.logger.Info("Using DLL path", "absolute_path", absPath)

	// Allocate memory for DLL path
	dllPathBytes := []byte(absPath + "\x00")
	pathSize := len(dllPathBytes)
	i.logger.Info("Allocating memory for DLL path", "path", absPath, "size", pathSize)

	memAddr, err := VirtualAllocEx(hProcess, 0, uintptr(pathSize),
		windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_READWRITE)
	if err != nil {
		i.logger.Error("Failed to allocate memory", "error", err, "size", pathSize)
		return fmt.Errorf("failed to allocate memory: %v", err)
	}
	i.logger.Info("Successfully allocated memory", "address", fmt.Sprintf("0x%X", memAddr))

	// Ensure memory is freed on error
	defer func() {
		if memAddr != 0 && err != nil {
			// Free memory on error
			VirtualFreeEx(hProcess, memAddr, 0, windows.MEM_RELEASE)
			i.logger.Debug("Freed allocated memory due to error", "address", fmt.Sprintf("0x%X", memAddr))
		}
	}()

	// Write DLL path to target process
	var bytesWritten uintptr
	err = WriteProcessMemory(hProcess, memAddr, unsafe.Pointer(&dllPathBytes[0]),
		uintptr(pathSize), &bytesWritten)
	if err != nil {
		i.logger.Error("Failed to write DLL path", "error", err, "address", fmt.Sprintf("0x%X", memAddr))
		return fmt.Errorf("failed to write DLL path: %v", err)
	}
	i.logger.Info("Successfully wrote DLL path", "bytes_written", bytesWritten, "expected", pathSize)

	// Verify the write was successful
	if bytesWritten != uintptr(pathSize) {
		i.logger.Error("Incomplete write", "written", bytesWritten, "expected", pathSize)
		return fmt.Errorf("incomplete write: wrote %d bytes, expected %d", bytesWritten, pathSize)
	}

	// Get LoadLibraryA address
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	loadLibraryA := kernel32.NewProc("LoadLibraryA")
	loadLibraryAddr := loadLibraryA.Addr()
	i.logger.Info("LoadLibraryA address", "address", fmt.Sprintf("0x%X", loadLibraryAddr))

	// Verify the DLL path exists
	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		i.logger.Error("DLL file does not exist", "path", absPath)
		return fmt.Errorf("DLL file does not exist: %s", absPath)
	}

	// Create remote thread
	var threadID uint32
	i.logger.Info("Creating remote thread", "entry_point", fmt.Sprintf("0x%X", loadLibraryAddr), "parameter", fmt.Sprintf("0x%X", memAddr))

	threadHandle, err := CreateRemoteThread(hProcess, nil, 0,
		loadLibraryAddr, memAddr, 0, &threadID)
	if err != nil {
		i.logger.Error("Failed to create remote thread", "error", err, "loadlibrary_addr", fmt.Sprintf("0x%X", loadLibraryAddr), "param_addr", fmt.Sprintf("0x%X", memAddr))
		return fmt.Errorf("failed to create remote thread: %v", err)
	}
	defer windows.CloseHandle(threadHandle)

	i.logger.Info("Successfully created remote thread", "thread_id", threadID, "handle", threadHandle)

	// Wait for thread completion with detailed logging
	i.logger.Info("Waiting for thread completion...")
	waitResult, err := windows.WaitForSingleObject(threadHandle, uint32(DefaultTimeoutMedium.Milliseconds()))
	if err != nil {
		i.logger.Error("Failed to wait for thread", "error", err)
		return fmt.Errorf("failed to wait for thread: %v", err)
	}

	switch waitResult {
	case uint32(windows.WAIT_TIMEOUT):
		i.logger.Error("Thread execution timed out")
		return fmt.Errorf("thread execution timed out after 10 seconds")
	case uint32(windows.WAIT_OBJECT_0):
		i.logger.Info("Thread completed successfully")

		// Get thread exit code (LoadLibrary return value)
		var exitCode uint32
		ret, _, _ := procGetExitCodeThread.Call(uintptr(threadHandle), uintptr(unsafe.Pointer(&exitCode)))
		if ret != 0 {
			i.logger.Info("Thread exit code", "code", exitCode, "hex", fmt.Sprintf("0x%X", exitCode))
			if exitCode == 0 {
				i.logger.Error("LoadLibrary failed - exit code 0")
				return fmt.Errorf("LoadLibrary failed - DLL could not be loaded. Check DLL dependencies and architecture")
			} else {
				i.logger.Info("LoadLibrary succeeded", "dll_base", fmt.Sprintf("0x%X", exitCode))
			}
		} else {
			i.logger.Warn("Failed to get thread exit code")
		}
	default:
		i.logger.Error("Unexpected wait result", "result", waitResult)
		return fmt.Errorf("unexpected wait result: %d", waitResult)
	}

	// Apply post-injection anti-detection techniques if requested
	if i.bypassOptions.ErasePEHeader || i.bypassOptions.EraseEntryPoint {
		i.logger.Info("Applying post-injection anti-detection techniques")
		i.logger.Warn("WARNING: PE/Entry point erasure with LoadLibrary-based injection may cause instability")

		// Wait for DLL to fully initialize before applying erasure
		time.Sleep(2 * time.Second)

		// Get the DLL base address from the thread exit code
		var exitCode uint32
		ret, _, _ := procGetExitCodeThread.Call(uintptr(threadHandle), uintptr(unsafe.Pointer(&exitCode)))
		if ret != 0 && exitCode != 0 {
			dllBaseAddress := uintptr(exitCode)

			// Erase PE header if requested (with extra caution)
			if i.bypassOptions.ErasePEHeader {
				i.logger.Warn("Applying PE header erasure - this may affect DLL functionality")
				if err := ErasePEHeaderSafely(hProcess, dllBaseAddress); err != nil {
					i.logger.Warn("Failed to erase PE header", "error", err)
				} else {
					i.logger.Info("PE header erased successfully (with safety measures)")
				}
			}

			// Erase entry point if requested (with extra caution)
			if i.bypassOptions.EraseEntryPoint {
				i.logger.Warn("Applying entry point erasure - this may affect DLL unloading")
				if err := EraseEntryPointSafely(hProcess, dllBaseAddress); err != nil {
					i.logger.Warn("Failed to erase entry point", "error", err)
				} else {
					i.logger.Info("Entry point erased successfully (with safety measures)")
				}
			}
		} else {
			i.logger.Warn("Could not get DLL base address for post-injection techniques")
		}
	}

	i.logger.Info("Standard injection completed successfully")
	return nil
}

// setWindowsHookExInject implements SetWindowsHookEx injection
func (i *Injector) setWindowsHookExInject() error {
	i.logger.Info("Using SetWindowsHookEx injection method")

	// Validate DLL file exists
	if _, err := os.Stat(i.dllPath); os.IsNotExist(err) {
		i.logger.Error("DLL file does not exist", "path", i.dllPath)
		return fmt.Errorf("DLL file does not exist: %s", i.dllPath)
	}

	// Get absolute path
	absPath, err := filepath.Abs(i.dllPath)
	if err != nil {
		i.logger.Warn("Failed to get absolute path", "error", err)
		absPath = i.dllPath
	}

	// Validate DLL exports the required hook function
	dllBytes, err := os.ReadFile(absPath)
	if err != nil {
		return fmt.Errorf("failed to read DLL: %v", err)
	}

	// Check if DLL has proper hook function exports
	if !i.validateHookDLL(dllBytes) {
		i.logger.Error("DLL does not export required hook procedures")
		return fmt.Errorf("DLL must export hook procedures like GetMsgProc, CallWndProc, etc.")
	}

	// Find target thread in the process
	threadID, err := i.findMainThreadID()
	if err != nil {
		i.logger.Error("Failed to find main thread", "error", err)
		return fmt.Errorf("failed to find main thread: %v", err)
	}

	// Load DLL to get module handle
	user32 := windows.NewLazySystemDLL("user32.dll")
	setWindowsHookEx := user32.NewProc("SetWindowsHookExW")
	unHookWindowsHookEx := user32.NewProc("UnhookWindowsHookEx")

	// Convert path to UTF-16
	absPathUTF16, err := windows.UTF16PtrFromString(absPath)
	if err != nil {
		return fmt.Errorf("failed to convert path to UTF-16: %v", err)
	}

	// Load library to get module handle
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	loadLibrary := kernel32.NewProc("LoadLibraryW")
	getModuleHandle := kernel32.NewProc("GetModuleHandleW")
	getProcAddress := kernel32.NewProc("GetProcAddress")

	// Get module handle for the DLL
	moduleHandle, _, _ := getModuleHandle.Call(uintptr(unsafe.Pointer(absPathUTF16)))
	if moduleHandle == 0 {
		// Load the library if not already loaded
		moduleHandle, _, _ = loadLibrary.Call(uintptr(unsafe.Pointer(absPathUTF16)))
		if moduleHandle == 0 {
			return fmt.Errorf("failed to load DLL module")
		}
	}

	// Try different hook procedures that might be exported
	hookProcNames := []string{"GetMsgProc", "CallWndProc", "DllMain", "HookProc"}
	var hookProcAddr uintptr

	for _, procName := range hookProcNames {
		procNamePtr, _ := windows.BytePtrFromString(procName)
		addr, _, _ := getProcAddress.Call(moduleHandle, uintptr(unsafe.Pointer(procNamePtr)))
		if addr != 0 {
			hookProcAddr = addr
			i.logger.Info("Found hook procedure", "name", procName, "address", fmt.Sprintf("0x%X", addr))
			break
		}
	}

	if hookProcAddr == 0 {
		return fmt.Errorf("no valid hook procedure found in DLL")
	}

	// Install different types of hooks to increase success rate
	hookTypes := []struct {
		hookType int
		name     string
	}{
		{3, "WH_GETMESSAGE"},
		{4, "WH_CALLWNDPROC"},
		{5, "WH_CBT"},
		{7, "WH_KEYBOARD"},
	}

	var successfulHooks []uintptr
	var lastErr error

	for _, hookType := range hookTypes {
		// Install hook for specific thread
		hookHandle, _, err := setWindowsHookEx.Call(
			uintptr(hookType.hookType), // Hook type
			hookProcAddr,               // Hook procedure address
			moduleHandle,               // Module handle
			uintptr(threadID))          // Target thread ID

		if hookHandle != 0 {
			i.logger.Info("Successfully installed hook",
				"type", hookType.name,
				"handle", fmt.Sprintf("0x%X", hookHandle),
				"thread_id", threadID)
			successfulHooks = append(successfulHooks, hookHandle)
		} else {
			i.logger.Warn("Failed to install hook", "type", hookType.name, "error", err)
			lastErr = err
		}
	}

	if len(successfulHooks) == 0 {
		return fmt.Errorf("failed to install any hooks: %v", lastErr)
	}

	// Trigger message processing to activate the hooks
	err = i.triggerMessageProcessing(threadID)
	if err != nil {
		i.logger.Warn("Failed to trigger message processing", "error", err)
	}

	// Cleanup hooks after a short delay (in production, you might want to keep them)
	go func() {
		time.Sleep(5 * time.Second)
		for _, hookHandle := range successfulHooks {
			unHookWindowsHookEx.Call(hookHandle)
		}
		i.logger.Info("Cleaned up hooks", "count", len(successfulHooks))
	}()

	// Apply post-injection anti-detection techniques if requested
	if i.bypassOptions.ErasePEHeader || i.bypassOptions.EraseEntryPoint {
		i.logger.Info("Applying post-injection anti-detection techniques for SetWindowsHookEx")

		// Open target process to apply anti-detection techniques
		hProcess, err := windows.OpenProcess(
			windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_READ,
			false, i.processID)
		if err == nil {
			defer windows.CloseHandle(hProcess)

			// Use the module handle as the base address
			dllBaseAddress := uintptr(moduleHandle)

			// Erase PE header if requested
			if i.bypassOptions.ErasePEHeader {
				if err := ErasePEHeader(hProcess, dllBaseAddress); err != nil {
					i.logger.Warn("Failed to erase PE header", "error", err)
				} else {
					i.logger.Info("PE header erased successfully")
				}
			}

			// Erase entry point if requested
			if i.bypassOptions.EraseEntryPoint {
				if err := EraseEntryPoint(hProcess, dllBaseAddress); err != nil {
					i.logger.Warn("Failed to erase entry point", "error", err)
				} else {
					i.logger.Info("Entry point erased successfully")
				}
			}
		} else {
			i.logger.Warn("Could not open process for post-injection techniques", "error", err)
		}
	}

	i.logger.Info("SetWindowsHookEx injection completed",
		"successful_hooks", len(successfulHooks),
		"thread_id", threadID)

	return nil
}

// validateHookDLL checks if DLL exports hook procedures
func (i *Injector) validateHookDLL(dllBytes []byte) bool {
	// Parse PE header to check exports
	peHeader, err := ParsePEHeader(dllBytes)
	if err != nil {
		i.logger.Warn("Failed to parse PE for hook validation", "error", err)
		return true // Allow attempt even if we can't validate
	}

	// In a full implementation, we would parse the export table
	// For now, just check if it's a valid PE file
	if peHeader != nil && len(peHeader.SectionHeaders) > 0 {
		return true
	}
	return false
}

// triggerMessageProcessing sends messages to trigger hook execution
func (i *Injector) triggerMessageProcessing(threadID uint32) error {
	user32 := windows.NewLazySystemDLL("user32.dll")
	postThreadMessage := user32.NewProc("PostThreadMessageW")

	// Send several different message types to trigger hook processing
	messages := []uint32{0x0400, 0x0401, 0x0402} // WM_USER variants

	for _, msg := range messages {
		ret, _, _ := postThreadMessage.Call(
			uintptr(threadID), // Target thread
			uintptr(msg),      // Message
			0,                 // wParam
			0)                 // lParam

		if ret != 0 {
			i.logger.Info("Sent trigger message", "thread_id", threadID, "message", fmt.Sprintf("0x%X", msg))
		}
	}

	return nil
}

// queueUserAPCInject implements QueueUserAPC injection
func (i *Injector) queueUserAPCInject() error {
	i.logger.Info("Using QueueUserAPC injection method")

	// Open target process with required permissions
	hProcess, err := windows.OpenProcess(
		windows.PROCESS_VM_OPERATION|
			windows.PROCESS_VM_WRITE|
			windows.PROCESS_VM_READ|
			windows.PROCESS_QUERY_INFORMATION|
			windows.PROCESS_SUSPEND_RESUME, // Added for thread manipulation
		false, i.processID)
	if err != nil {
		i.logger.Error("Failed to open target process", "error", err)
		return fmt.Errorf("failed to open target process: %v", err)
	}
	defer windows.CloseHandle(hProcess)

	// Get absolute DLL path
	absPath, err := filepath.Abs(i.dllPath)
	if err != nil {
		i.logger.Warn("Failed to get absolute path", "error", err)
		absPath = i.dllPath
	}

	// Find all alertable threads in the target process
	alertableThreads, err := i.findAlertableThreads()
	if err != nil {
		i.logger.Error("Failed to find alertable threads", "error", err)
		return fmt.Errorf("failed to find alertable threads: %v", err)
	}

	if len(alertableThreads) == 0 {
		i.logger.Warn("No alertable threads found, attempting to create alertable state")
		// Try to make threads alertable by suspending and resuming them
		alertableThreads, err = i.makeThreadsAlertable()
		if err != nil {
			return fmt.Errorf("failed to make threads alertable: %v", err)
		}
	}

	// Allocate memory and write DLL path
	dllPathBytes := []byte(absPath + "\x00")
	pathSize := len(dllPathBytes)

	memAddr, err := VirtualAllocEx(hProcess, 0, uintptr(pathSize),
		windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_READWRITE)
	if err != nil {
		i.logger.Error("Failed to allocate memory", "error", err)
		return fmt.Errorf("failed to allocate memory: %v", err)
	}

	// Ensure memory is freed in all cases
	success := false
	defer func() {
		if !success && memAddr != 0 {
			VirtualFreeEx(hProcess, memAddr, 0, windows.MEM_RELEASE)
			i.logger.Debug("Freed allocated memory", "address", fmt.Sprintf("0x%X", memAddr))
		}
	}()

	var bytesWritten uintptr
	err = WriteProcessMemory(hProcess, memAddr, unsafe.Pointer(&dllPathBytes[0]),
		uintptr(pathSize), &bytesWritten)
	if err != nil {
		i.logger.Error("Failed to write DLL path", "error", err)
		return fmt.Errorf("failed to write DLL path: %v", err)
	}

	// Get LoadLibraryA address
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	loadLibraryA := kernel32.NewProc("LoadLibraryA")
	loadLibraryAddr := loadLibraryA.Addr()

	i.logger.Info("LoadLibraryA address", "address", fmt.Sprintf("0x%X", loadLibraryAddr))

	// Queue APC to multiple threads to increase success rate
	queueUserAPC := kernel32.NewProc("QueueUserAPC")
	successCount := 0

	for _, threadHandle := range alertableThreads {
		ret, _, err := queueUserAPC.Call(
			loadLibraryAddr,       // APC routine (LoadLibraryA)
			uintptr(threadHandle), // Thread handle
			memAddr)               // APC parameter (DLL path)

		if ret != 0 {
			successCount++
			i.logger.Info("Successfully queued APC",
				"thread", fmt.Sprintf("0x%X", threadHandle),
				"dll_path_addr", fmt.Sprintf("0x%X", memAddr))
		} else {
			i.logger.Warn("Failed to queue APC",
				"thread", fmt.Sprintf("0x%X", threadHandle),
				"error", err)
		}
	}

	// Clean up thread handles with error handling
	for idx, threadHandle := range alertableThreads {
		if err := windows.CloseHandle(threadHandle); err != nil {
			i.logger.Warn("Failed to close thread handle", "index", idx, "error", err)
		}
	}

	if successCount == 0 {
		return fmt.Errorf("failed to queue APC to any thread")
	}

	// Try to trigger APC execution by sending signals to threads
	err = i.triggerAPCExecution()
	if err != nil {
		i.logger.Warn("Failed to trigger APC execution", "error", err)
	}

	// Apply post-injection anti-detection techniques if requested
	if i.bypassOptions.ErasePEHeader || i.bypassOptions.EraseEntryPoint {
		i.logger.Info("Applying post-injection anti-detection techniques for QueueUserAPC")

		// Wait a moment for DLL to load before applying techniques
		time.Sleep(1 * time.Second)

		// Try to find the loaded DLL base address
		// For APC injection, we need to enumerate loaded modules to find our DLL
		dllBaseAddress, err := i.findLoadedDLLBaseAddress(hProcess, absPath)
		if err != nil {
			i.logger.Warn("Could not find loaded DLL base address", "error", err)
		} else {
			// Erase PE header if requested
			if i.bypassOptions.ErasePEHeader {
				if err := ErasePEHeader(hProcess, dllBaseAddress); err != nil {
					i.logger.Warn("Failed to erase PE header", "error", err)
				} else {
					i.logger.Info("PE header erased successfully")
				}
			}

			// Erase entry point if requested
			if i.bypassOptions.EraseEntryPoint {
				if err := EraseEntryPoint(hProcess, dllBaseAddress); err != nil {
					i.logger.Warn("Failed to erase entry point", "error", err)
				} else {
					i.logger.Info("Entry point erased successfully")
				}
			}
		}
	}

	i.logger.Info("QueueUserAPC injection completed",
		"successful_apc_count", successCount,
		"total_threads", len(alertableThreads))

	return nil
}

// earlyBirdAPCInject implements Early Bird APC injection
func (i *Injector) earlyBirdAPCInject() error {
	i.logger.Info("Using Early Bird APC injection method")

	// Early Bird APC works by suspending the process, queuing APCs to all threads,
	// then resuming. This ensures APCs execute early in the process lifecycle.

	// Open target process with required permissions
	hProcess, err := windows.OpenProcess(
		windows.PROCESS_ALL_ACCESS,
		false, i.processID)
	if err != nil {
		i.logger.Error("Failed to open target process", "error", err)
		return fmt.Errorf("failed to open target process: %v", err)
	}
	defer windows.CloseHandle(hProcess)

	// Find and suspend all threads in the target process
	suspendedThreads, err := i.suspendAllThreads()
	if err != nil {
		i.logger.Error("Failed to suspend threads", "error", err)
		return fmt.Errorf("failed to suspend threads: %v", err)
	}

	i.logger.Info("Suspended threads for EarlyBird APC", "count", len(suspendedThreads))

	// Ensure threads are resumed even if injection fails
	defer func() {
		for _, threadHandle := range suspendedThreads {
			windows.ResumeThread(threadHandle)
			windows.CloseHandle(threadHandle)
		}
		i.logger.Info("Resumed all suspended threads")
	}()

	// Get absolute DLL path
	absPath, err := filepath.Abs(i.dllPath)
	if err != nil {
		absPath = i.dllPath
	}

	// Allocate memory and write DLL path
	dllPathBytes := []byte(absPath + "\x00")
	pathSize := len(dllPathBytes)

	memAddr, err := VirtualAllocEx(hProcess, 0, uintptr(pathSize),
		windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_READWRITE)
	if err != nil {
		i.logger.Error("Failed to allocate memory", "error", err)
		return fmt.Errorf("failed to allocate memory: %v", err)
	}

	// Ensure memory is freed properly
	defer func() {
		if memAddr != 0 {
			VirtualFreeEx(hProcess, memAddr, 0, windows.MEM_RELEASE)
			i.logger.Debug("Freed allocated memory", "address", fmt.Sprintf("0x%X", memAddr))
		}
	}()

	var bytesWritten uintptr
	err = WriteProcessMemory(hProcess, memAddr, unsafe.Pointer(&dllPathBytes[0]),
		uintptr(pathSize), &bytesWritten)
	if err != nil {
		i.logger.Error("Failed to write DLL path", "error", err)
		return fmt.Errorf("failed to write DLL path: %v", err)
	}

	// Get LoadLibraryA address
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	loadLibraryA := kernel32.NewProc("LoadLibraryA")
	loadLibraryAddr := loadLibraryA.Addr()

	i.logger.Info("LoadLibraryA address", "address", fmt.Sprintf("0x%X", loadLibraryAddr))

	// Queue APC to all suspended threads (EarlyBird technique)
	queueUserAPC := kernel32.NewProc("QueueUserAPC")
	successCount := 0

	for _, threadHandle := range suspendedThreads {
		ret, _, err := queueUserAPC.Call(
			loadLibraryAddr,       // APC routine (LoadLibraryA)
			uintptr(threadHandle), // Thread handle
			memAddr)               // APC parameter (DLL path)

		if ret != 0 {
			successCount++
			i.logger.Info("Successfully queued EarlyBird APC",
				"thread", fmt.Sprintf("0x%X", threadHandle))
		} else {
			i.logger.Warn("Failed to queue EarlyBird APC",
				"thread", fmt.Sprintf("0x%X", threadHandle),
				"error", err)
		}
	}

	if successCount == 0 {
		return fmt.Errorf("failed to queue APC to any thread")
	}

	// Add a short delay before resuming threads to ensure APC is properly queued
	time.Sleep(100 * time.Millisecond)

	// Apply post-injection anti-detection techniques if requested
	if i.bypassOptions.ErasePEHeader || i.bypassOptions.EraseEntryPoint {
		i.logger.Info("Applying post-injection anti-detection techniques for EarlyBird APC")

		// Wait a moment for DLL to load before applying techniques
		time.Sleep(1 * time.Second)

		// Try to find the loaded DLL base address
		dllBaseAddress, err := i.findLoadedDLLBaseAddress(hProcess, absPath)
		if err != nil {
			i.logger.Warn("Could not find loaded DLL base address", "error", err)
		} else {
			// Erase PE header if requested
			if i.bypassOptions.ErasePEHeader {
				if err := ErasePEHeader(hProcess, dllBaseAddress); err != nil {
					i.logger.Warn("Failed to erase PE header", "error", err)
				} else {
					i.logger.Info("PE header erased successfully")
				}
			}

			// Erase entry point if requested
			if i.bypassOptions.EraseEntryPoint {
				if err := EraseEntryPoint(hProcess, dllBaseAddress); err != nil {
					i.logger.Warn("Failed to erase entry point", "error", err)
				} else {
					i.logger.Info("Entry point erased successfully")
				}
			}
		}
	}

	i.logger.Info("EarlyBird APC injection completed",
		"successful_apc_count", successCount,
		"total_threads", len(suspendedThreads))

	// Threads will be resumed by the defer function
	return nil
}

// dllNotificationInject implements DLL notification injection
func (i *Injector) dllNotificationInject() error {
	i.logger.Info("Using DLL notification injection method")

	// DLL Notification injection uses LdrRegisterDllNotification to hook DLL loads
	// This is a more advanced technique that requires careful implementation

	// Open target process
	hProcess, err := windows.OpenProcess(
		windows.PROCESS_ALL_ACCESS,
		false, i.processID)
	if err != nil {
		i.logger.Error("Failed to open target process", "error", err)
		return fmt.Errorf("failed to open target process: %v", err)
	}
	defer windows.CloseHandle(hProcess)

	// Get absolute DLL path
	absPath, err := filepath.Abs(i.dllPath)
	if err != nil {
		absPath = i.dllPath
	}

	// For DLL notification injection, we need to:
	// 1. Create a notification callback that will load our DLL
	// 2. Register the notification in the target process
	// 3. Trigger a DLL load event to activate our callback

	// Since this requires complex shellcode and callback management,
	// we'll implement a simplified version that uses manual DLL mapping
	// combined with notification-like behavior

	i.logger.Info("Implementing DLL notification via manual mapping")

	// Read DLL bytes
	dllBytes, err := os.ReadFile(absPath)
	if err != nil {
		i.logger.Error("Failed to read DLL file", "error", err)
		return fmt.Errorf("failed to read DLL file: %v", err)
	}

	// Perform manual mapping to simulate notification-based loading
	baseAddress, err := i.manualMapDLLWithOptions(hProcess, dllBytes)
	if err != nil {
		i.logger.Error("Manual mapping failed", "error", err)
		return fmt.Errorf("manual mapping failed: %v", err)
	}

	i.logger.Info("DLL notification injection successful", "base_address", fmt.Sprintf("0x%X", baseAddress))

	// Apply enhanced techniques if configured
	if i.useEnhancedOptions {
		err = i.applyEnhancedInjectionTechniques(hProcess, baseAddress, uintptr(len(dllBytes)), dllBytes)
		if err != nil {
			i.logger.Warn("Enhanced techniques failed", "error", err)
		}
	}

	return nil
}

// cryoBirdInject implements CryoBird (job object freeze) injection
func (i *Injector) cryoBirdInject() error {
	i.logger.Info("Using CryoBird (job object freeze) injection method")

	// Create job object with specific limits to freeze the process
	jobHandle, err := CreateJobObject(nil, nil)
	if err != nil {
		i.logger.Error("Failed to create job object", "error", err)
		return fmt.Errorf("failed to create job object: %v", err)
	}
	defer windows.CloseHandle(jobHandle)

	// Configure job object to suspend processes
	err = i.configureJobObjectForSuspension(jobHandle)
	if err != nil {
		i.logger.Error("Failed to configure job object", "error", err)
		return fmt.Errorf("failed to configure job object: %v", err)
	}

	// Open target process with full access
	hProcess, err := windows.OpenProcess(
		windows.PROCESS_ALL_ACCESS,
		false, i.processID)
	if err != nil {
		i.logger.Error("Failed to open target process", "error", err)
		return fmt.Errorf("failed to open target process: %v", err)
	}
	defer windows.CloseHandle(hProcess)

	// Assign process to job object (this applies the suspension)
	err = AssignProcessToJobObject(jobHandle, hProcess)
	if err != nil {
		i.logger.Error("Failed to assign process to job", "error", err)
		return fmt.Errorf("failed to assign process to job: %v", err)
	}

	i.logger.Info("Process frozen in job object, performing injection")

	// Ensure process is unfrozen even if injection fails
	defer func() {
		err := TerminateJobObject(jobHandle, 0)
		if err != nil {
			i.logger.Warn("Failed to terminate job object", "error", err)
		} else {
			i.logger.Info("Process unfrozen")
		}
	}()

	// Perform injection while process is frozen
	// Use direct memory manipulation since threads are suspended
	absPath, err := filepath.Abs(i.dllPath)
	if err != nil {
		absPath = i.dllPath
	}

	dllPathBytes := []byte(absPath + "\x00")
	pathSize := len(dllPathBytes)

	// Allocate memory for DLL path
	memAddr, err := VirtualAllocEx(hProcess, 0, uintptr(pathSize),
		windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_READWRITE)
	if err != nil {
		i.logger.Error("Failed to allocate memory", "error", err)
		return fmt.Errorf("failed to allocate memory: %v", err)
	}

	// Ensure memory is freed properly
	defer func() {
		if memAddr != 0 {
			VirtualFreeEx(hProcess, memAddr, 0, windows.MEM_RELEASE)
			i.logger.Debug("Freed allocated memory", "address", fmt.Sprintf("0x%X", memAddr))
		}
	}()

	// Write DLL path
	var bytesWritten uintptr
	err = WriteProcessMemory(hProcess, memAddr, unsafe.Pointer(&dllPathBytes[0]),
		uintptr(pathSize), &bytesWritten)
	if err != nil {
		i.logger.Error("Failed to write DLL path", "error", err)
		return fmt.Errorf("failed to write DLL path: %v", err)
	}

	// Get LoadLibrary address using direct function resolution
	loadLibraryAddr, err := i.resolveLoadLibraryAddress()
	if err != nil {
		return fmt.Errorf("failed to resolve LoadLibrary address: %v", err)
	}

	// Create remote thread to load the DLL while process is frozen
	var threadID uint32
	threadHandle, err := CreateRemoteThread(hProcess, nil, 0, loadLibraryAddr, memAddr, 0, &threadID)
	if err != nil {
		i.logger.Error("Failed to create remote thread", "error", err)
		return fmt.Errorf("failed to create remote thread: %v", err)
	}
	defer windows.CloseHandle(threadHandle)

	i.logger.Info("Created remote thread while process frozen", "thread_id", threadID)

	// Wait for thread completion with extended timeout
	waitResult, err := windows.WaitForSingleObject(threadHandle, 15000)
	if err != nil {
		return fmt.Errorf("failed to wait for thread: %v", err)
	}

	if waitResult == uint32(windows.WAIT_TIMEOUT) {
		return fmt.Errorf("thread execution timed out")
	}

	// Get the loaded DLL base address
	var exitCode uint32
	ret, _, _ := procGetExitCodeThread.Call(uintptr(threadHandle), uintptr(unsafe.Pointer(&exitCode)))
	if ret == 0 || exitCode == 0 {
		return fmt.Errorf("DLL loading failed - LoadLibrary returned NULL")
	}

	dllBaseAddress := uintptr(exitCode)
	i.logger.Info("DLL loaded successfully while frozen", "base_address", fmt.Sprintf("0x%X", dllBaseAddress))

	i.logger.Info("CryoBird injection successful")
	return nil
}

// Helper functions for thread management and process validation

// findAlertableThreads finds all threads that can be made alertable
func (i *Injector) findAlertableThreads() ([]windows.Handle, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snapshot)

	var alertableThreads []windows.Handle
	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))

	err = windows.Thread32First(snapshot, &te)
	if err != nil {
		return nil, err
	}

	for {
		if te.OwnerProcessID == i.processID {
			// Open thread with required permissions
			threadHandle, err := windows.OpenThread(
				windows.THREAD_SET_CONTEXT|windows.THREAD_SUSPEND_RESUME|
					windows.THREAD_GET_CONTEXT|windows.THREAD_QUERY_INFORMATION,
				false, te.ThreadID)

			if err == nil {
				alertableThreads = append(alertableThreads, threadHandle)
				i.logger.Info("Found thread for APC", "thread_id", te.ThreadID)
			} else {
				i.logger.Warn("Failed to open thread", "thread_id", te.ThreadID, "error", err)
			}
		}

		err = windows.Thread32Next(snapshot, &te)
		if err != nil {
			break
		}
	}

	return alertableThreads, nil
}

// makeThreadsAlertable attempts to make threads alertable by suspending/resuming
func (i *Injector) makeThreadsAlertable() ([]windows.Handle, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snapshot)

	var alertableThreads []windows.Handle
	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))

	err = windows.Thread32First(snapshot, &te)
	if err != nil {
		return nil, err
	}

	for {
		if te.OwnerProcessID == i.processID {
			threadHandle, err := windows.OpenThread(
				windows.THREAD_SET_CONTEXT|windows.THREAD_SUSPEND_RESUME|
					windows.THREAD_GET_CONTEXT|windows.THREAD_QUERY_INFORMATION,
				false, te.ThreadID)

			if err == nil {
				// Briefly suspend and resume to make thread alertable
				suspendCount, _, _ := procSuspendThread.Call(uintptr(threadHandle))
				if suspendCount != 0xFFFFFFFF {
					windows.ResumeThread(threadHandle)
					alertableThreads = append(alertableThreads, threadHandle)
					i.logger.Info("Made thread alertable", "thread_id", te.ThreadID)
				} else {
					windows.CloseHandle(threadHandle)
				}
			}
		}

		err = windows.Thread32Next(snapshot, &te)
		if err != nil {
			break
		}
	}

	return alertableThreads, nil
}

// triggerAPCExecution attempts to trigger APC execution
func (i *Injector) triggerAPCExecution() error {
	// Send various signals to the process to trigger APC execution
	user32 := windows.NewLazySystemDLL("user32.dll")
	postMessage := user32.NewProc("PostMessageW")

	// Try to find the main window of the process
	hWnd, err := i.findProcessMainWindow()
	if err == nil && hWnd != 0 {
		// Send messages that might trigger APC execution
		messages := []uint32{0x0000, 0x0001, 0x0002, 0x0400} // WM_NULL, WM_CREATE, WM_DESTROY, WM_USER

		for _, msg := range messages {
			postMessage.Call(uintptr(hWnd), uintptr(msg), 0, 0)
		}

		i.logger.Info("Sent trigger messages to main window", "hwnd", fmt.Sprintf("0x%X", hWnd))
	}

	return nil
}

// findProcessMainWindow finds the main window of the target process
func (i *Injector) findProcessMainWindow() (uintptr, error) {
	// This is a simplified implementation
	// In reality, you would enumerate windows to find the main window of the process
	user32 := windows.NewLazySystemDLL("user32.dll")
	findWindow := user32.NewProc("FindWindowW")

	// Try to find any window (this is very basic)
	hWnd, _, _ := findWindow.Call(0, 0)
	return hWnd, nil
}

// suspendAllThreads suspends all threads in the target process
func (i *Injector) suspendAllThreads() ([]windows.Handle, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snapshot)

	var suspendedThreads []windows.Handle
	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))

	err = windows.Thread32First(snapshot, &te)
	if err != nil {
		return nil, err
	}

	for {
		if te.OwnerProcessID == i.processID {
			threadHandle, err := windows.OpenThread(
				windows.THREAD_SUSPEND_RESUME|windows.THREAD_QUERY_INFORMATION,
				false, te.ThreadID)

			if err == nil {
				suspendCount, _, _ := procSuspendThread.Call(uintptr(threadHandle))
				if suspendCount != 0xFFFFFFFF {
					suspendedThreads = append(suspendedThreads, threadHandle)
					i.logger.Info("Suspended thread", "thread_id", te.ThreadID)
				} else {
					windows.CloseHandle(threadHandle)
				}
			} else {
				i.logger.Warn("Failed to open thread for suspension", "thread_id", te.ThreadID, "error", err)
			}
		}

		err = windows.Thread32Next(snapshot, &te)
		if err != nil {
			break
		}
	}

	return suspendedThreads, nil
}

// configureJobObjectForSuspension configures job object to suspend processes
func (i *Injector) configureJobObjectForSuspension(jobHandle windows.Handle) error {
	i.logger.Info("Configuring job object for process suspension")

	// Define job object basic limit information
	type JobObjectBasicLimitInformation struct {
		PerProcessUserTimeLimit uint64
		PerJobUserTimeLimit     uint64
		LimitFlags              uint32
		MinimumWorkingSetSize   uintptr
		MaximumWorkingSetSize   uintptr
		ActiveProcessLimit      uint32
		Affinity                uintptr
		PriorityClass           uint32
		SchedulingClass         uint32
	}

	// Set up basic limits
	var basicLimits JobObjectBasicLimitInformation
	basicLimits.LimitFlags = 0x00000020 // JOB_OBJECT_LIMIT_SUSPEND_RESUME
	basicLimits.ActiveProcessLimit = 1

	// Set job object information
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	setInformationJobObject := kernel32.NewProc("SetInformationJobObject")

	ret, _, _ := setInformationJobObject.Call(
		uintptr(jobHandle),
		2, // JobObjectBasicLimitInformation
		uintptr(unsafe.Pointer(&basicLimits)),
		unsafe.Sizeof(basicLimits),
	)

	if ret == 0 {
		return fmt.Errorf("failed to configure job object limits")
	}

	i.logger.Info("Job object configured successfully for process suspension")
	return nil
}

// resolveLoadLibraryAddress resolves LoadLibraryA address directly
func (i *Injector) resolveLoadLibraryAddress() (uintptr, error) {
	if i.bypassOptions.DirectSyscalls {
		// Use direct system calls to avoid API hooks
		return i.resolveLoadLibraryViaSyscalls()
	}

	// Standard method
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	loadLibraryA := kernel32.NewProc("LoadLibraryA")
	return loadLibraryA.Addr(), nil
}

// resolveLoadLibraryViaSyscalls resolves LoadLibrary using direct syscalls
func (i *Injector) resolveLoadLibraryViaSyscalls() (uintptr, error) {
	i.logger.Info("Resolving LoadLibrary via direct syscalls")

	// Use LdrGetProcedureAddress to resolve LoadLibraryA from kernel32
	// This is less likely to be hooked than GetProcAddress
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	ldrGetProcedureAddress := ntdll.NewProc("LdrGetProcedureAddress")

	// Get kernel32 module handle
	kernel32Handle, err := windows.LoadLibrary("kernel32.dll")
	if err != nil {
		i.logger.Warn("Failed to get kernel32 handle, using standard method")
		kernel32 := windows.NewLazySystemDLL("kernel32.dll")
		loadLibraryA := kernel32.NewProc("LoadLibraryA")
		return loadLibraryA.Addr(), nil
	}

	// Create ANSI_STRING for "LoadLibraryA"
	functionName := "LoadLibraryA"
	var ansiString struct {
		Length        uint16
		MaximumLength uint16
		Buffer        *byte
	}

	functionNameBytes := []byte(functionName)
	ansiString.Length = uint16(len(functionNameBytes))
	ansiString.MaximumLength = uint16(len(functionNameBytes))
	ansiString.Buffer = &functionNameBytes[0]

	var functionAddr uintptr

	// Call LdrGetProcedureAddress
	ret, _, _ := ldrGetProcedureAddress.Call(
		uintptr(kernel32Handle),
		uintptr(unsafe.Pointer(&ansiString)),
		0, // Ordinal (0 means use name)
		uintptr(unsafe.Pointer(&functionAddr)),
	)

	if ret != 0 || functionAddr == 0 {
		i.logger.Warn("LdrGetProcedureAddress failed, using standard method")
		kernel32 := windows.NewLazySystemDLL("kernel32.dll")
		loadLibraryA := kernel32.NewProc("LoadLibraryA")
		return loadLibraryA.Addr(), nil
	}

	i.logger.Info("Successfully resolved LoadLibraryA via LdrGetProcedureAddress",
		"address", fmt.Sprintf("0x%X", functionAddr))

	return functionAddr, nil
}

// Windows API function declarations

var (
	kernel32                     = windows.NewLazySystemDLL("kernel32.dll")
	procVirtualAllocEx           = kernel32.NewProc("VirtualAllocEx")
	procVirtualFreeEx            = kernel32.NewProc("VirtualFreeEx")
	procWriteProcessMemory       = kernel32.NewProc("WriteProcessMemory")
	procCreateRemoteThread       = kernel32.NewProc("CreateRemoteThread")
	procCreateJobObjectW         = kernel32.NewProc("CreateJobObjectW")
	procAssignProcessToJobObject = kernel32.NewProc("AssignProcessToJobObject")
	procTerminateJobObject       = kernel32.NewProc("TerminateJobObject")
	procGetExitCodeThread        = kernel32.NewProc("GetExitCodeThread")
	procSuspendThread            = kernel32.NewProc("SuspendThread")
)

// VirtualAllocEx allocates memory in another process
func VirtualAllocEx(hProcess windows.Handle, lpAddress uintptr, dwSize uintptr, flAllocationType uint32, flProtect uint32) (uintptr, error) {
	ret, _, err := procVirtualAllocEx.Call(
		uintptr(hProcess),
		lpAddress,
		dwSize,
		uintptr(flAllocationType),
		uintptr(flProtect))
	if ret == 0 {
		return 0, err
	}
	return ret, nil
}

// VirtualFreeEx frees memory in another process
func VirtualFreeEx(hProcess windows.Handle, lpAddress uintptr, dwSize uintptr, dwFreeType uint32) error {
	ret, _, err := procVirtualFreeEx.Call(
		uintptr(hProcess),
		lpAddress,
		dwSize,
		uintptr(dwFreeType))
	if ret == 0 {
		return err
	}
	return nil
}

// WriteProcessMemory writes memory to another process
func WriteProcessMemory(hProcess windows.Handle, lpBaseAddress uintptr, lpBuffer unsafe.Pointer, nSize uintptr, lpNumberOfBytesWritten *uintptr) error {
	ret, _, err := procWriteProcessMemory.Call(
		uintptr(hProcess),
		lpBaseAddress,
		uintptr(lpBuffer),
		nSize,
		uintptr(unsafe.Pointer(lpNumberOfBytesWritten)))
	if ret == 0 {
		return err
	}
	return nil
}

// CreateRemoteThread creates a thread in another process
func CreateRemoteThread(hProcess windows.Handle, lpThreadAttributes unsafe.Pointer, dwStackSize uintptr, lpStartAddress uintptr, lpParameter uintptr, dwCreationFlags uint32, lpThreadId *uint32) (windows.Handle, error) {
	ret, _, err := procCreateRemoteThread.Call(
		uintptr(hProcess),
		uintptr(lpThreadAttributes),
		dwStackSize,
		lpStartAddress,
		lpParameter,
		uintptr(dwCreationFlags),
		uintptr(unsafe.Pointer(lpThreadId)))
	if ret == 0 {
		return 0, err
	}
	return windows.Handle(ret), nil
}

// CreateJobObject creates a job object
func CreateJobObject(lpJobAttributes unsafe.Pointer, lpName unsafe.Pointer) (windows.Handle, error) {
	ret, _, err := procCreateJobObjectW.Call(
		uintptr(lpJobAttributes),
		uintptr(lpName))
	if ret == 0 {
		return 0, err
	}
	return windows.Handle(ret), nil
}

// AssignProcessToJobObject assigns a process to a job object
func AssignProcessToJobObject(hJob windows.Handle, hProcess windows.Handle) error {
	ret, _, err := procAssignProcessToJobObject.Call(
		uintptr(hJob),
		uintptr(hProcess))
	if ret == 0 {
		return err
	}
	return nil
}

// TerminateJobObject terminates all processes in a job object
func TerminateJobObject(hJob windows.Handle, uExitCode uint32) error {
	ret, _, err := procTerminateJobObject.Call(
		uintptr(hJob),
		uintptr(uExitCode))
	if ret == 0 {
		return err
	}
	return nil
}

// findMainThreadID finds the main thread of the process
func (i *Injector) findMainThreadID() (uint32, error) {
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

	// Return the first thread found for the target process
	for {
		if te.OwnerProcessID == i.processID {
			i.logger.Info("Found main thread", "thread_id", te.ThreadID)
			return te.ThreadID, nil
		}

		err = windows.Thread32Next(snapshot, &te)
		if err != nil {
			break
		}
	}

	return 0, fmt.Errorf("no threads found for process %d", i.processID)
}

// validateTargetProcess validates the target process
func (i *Injector) validateTargetProcess() error {
	i.logger.Info("Validating target process", "pid", i.processID)

	// Open process to check if it exists and is accessible
	hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, i.processID)
	if err != nil {
		i.logger.Error("Cannot access target process", "error", err)
		return fmt.Errorf("cannot access target process %d: %v", i.processID, err)
	}
	defer windows.CloseHandle(hProcess)

	// Check if process is still running
	var exitCode uint32
	err = windows.GetExitCodeProcess(hProcess, &exitCode)
	if err == nil && exitCode != 259 { // STILL_ACTIVE = 259
		return fmt.Errorf("target process %d has exited (exit code: %d)", i.processID, exitCode)
	}

	// Check process architecture
	is64Bit, err := IsProcess64Bit(i.processID)
	if err != nil {
		return fmt.Errorf("failed to determine process architecture: %v", err)
	}

	currentArch := "32-bit"
	if unsafe.Sizeof(uintptr(0)) == 8 {
		currentArch = "64-bit"
	}

	targetArch := "32-bit"
	if is64Bit {
		targetArch = "64-bit"
	}

	i.logger.Info("Target process validation successful",
		"target_arch", targetArch,
		"current_arch", currentArch)

	return nil
}

// validateDLLArchitecture validates DLL architecture compatibility
func (i *Injector) validateDLLArchitecture() error {
	i.logger.Info("Validating DLL architecture", "dll", i.dllPath)

	// Read DLL file to check architecture
	dllBytes, err := os.ReadFile(i.dllPath)
	if err != nil {
		return fmt.Errorf("failed to read DLL file: %v", err)
	}

	// Basic PE validation
	if len(dllBytes) < 64 {
		return fmt.Errorf("file too small to be a valid PE")
	}

	// Check DOS signature
	if dllBytes[0] != 'M' || dllBytes[1] != 'Z' {
		return fmt.Errorf("invalid DOS signature")
	}

	// Get PE offset
	peOffset := *(*uint32)(unsafe.Pointer(&dllBytes[60]))
	if peOffset >= uint32(len(dllBytes)) || peOffset < 64 {
		return fmt.Errorf("invalid PE offset: %d", peOffset)
	}

	// Check PE signature
	if peOffset+4 > uint32(len(dllBytes)) {
		return fmt.Errorf("PE signature out of bounds")
	}

	if dllBytes[peOffset] != 'P' || dllBytes[peOffset+1] != 'E' {
		return fmt.Errorf("invalid PE signature")
	}

	// Check machine type
	if peOffset+24 > uint32(len(dllBytes)) {
		return fmt.Errorf("machine type out of bounds")
	}

	machine := *(*uint16)(unsafe.Pointer(&dllBytes[peOffset+4]))

	var dllArch string
	switch machine {
	case 0x14c: // IMAGE_FILE_MACHINE_I386
		dllArch = "32-bit"
	case 0x8664: // IMAGE_FILE_MACHINE_AMD64
		dllArch = "64-bit"
	default:
		dllArch = fmt.Sprintf("unknown (0x%x)", machine)
	}

	i.logger.Info("DLL architecture detected", "architecture", dllArch, "machine_type", fmt.Sprintf("0x%x", machine))

	// Validate characteristics
	if peOffset+22 >= uint32(len(dllBytes)) {
		return fmt.Errorf("characteristics beyond file end")
	}

	characteristics := *(*uint16)(unsafe.Pointer(&dllBytes[peOffset+22]))
	isDll := characteristics&0x2000 != 0 // IMAGE_FILE_DLL

	if !isDll {
		i.logger.Warn("File does not have DLL characteristic flag set")
	}

	i.logger.Info("DLL validation completed", "is_dll", isDll)
	return nil
}

// attemptInjectionWithRecovery attempts injection with automatic fallback to other methods
func (i *Injector) attemptInjectionWithRecovery(dllBytes []byte) error {
	i.logger.Info("Starting injection with automatic recovery enabled")

	// Create a list of injection strategies to try
	strategies := i.buildInjectionStrategies(dllBytes)

	var lastError error
	var attemptedMethods []string

	for idx, strategy := range strategies {
		i.logger.Info("Attempting injection strategy", "index", idx+1, "total", len(strategies),
			"method", strategy.Name, "description", strategy.Description)

		// Apply strategy configuration
		originalMethod := i.method
		originalBypass := i.bypassOptions

		i.method = strategy.Method
		i.bypassOptions = strategy.BypassOptions

		// Attempt injection
		err := i.executeInjectionStrategy(strategy, dllBytes)

		// Track attempted methods
		attemptedMethods = append(attemptedMethods, strategy.Name)

		if err == nil {
			i.logger.Info("Injection successful with strategy", "method", strategy.Name,
				"attempts", len(attemptedMethods))
			return nil
		}

		i.logger.Warn("Injection strategy failed", "method", strategy.Name, "error", err)
		lastError = err

		// Restore original configuration
		i.method = originalMethod
		i.bypassOptions = originalBypass

		// Check if we should continue trying other methods
		if !i.shouldContinueRecovery(err, idx, len(strategies)) {
			i.logger.Info("Stopping recovery attempts", "reason", "non-recoverable error or strategy limit")
			break
		}

		// Small delay between attempts to avoid overwhelming the target
		time.Sleep(100 * time.Millisecond)
	}

	// All strategies failed
	return fmt.Errorf("all injection strategies failed (tried: %v). Last error: %v",
		attemptedMethods, lastError)
}

// InjectionStrategy represents a specific injection approach
type InjectionStrategy struct {
	Name          string
	Description   string
	Method        InjectionMethod
	BypassOptions BypassOptions
	Priority      int
	Compatibility []string // Target process types this works well with
}

// buildInjectionStrategies creates a prioritized list of injection strategies with architecture awareness
func (i *Injector) buildInjectionStrategies(dllBytes []byte) []InjectionStrategy {
	i.logger.Info("Building injection strategies with automatic architecture optimization")

	var strategies []InjectionStrategy

	// Perform automatic architecture detection for strategy optimization
	archCompat, err := ValidateDLLCompatibility(i.processID, dllBytes)
	if err != nil {
		i.logger.Warn("Could not detect architecture for strategy optimization", "error", err)
		// Continue with default strategies if detection fails
	} else {
		i.logger.Info("Architecture-aware strategy building",
			"process_arch", archCompat.ProcessArch.ProcessArch,
			"dll_arch", archCompat.DLLArch.Architecture,
			"is_wow64", archCompat.ProcessArch.IsWow64)
	}

	// Strategy 1: User's preferred method first (if not already failed)
	if i.shouldTryMethod(i.method) {
		strategies = append(strategies, InjectionStrategy{
			Name:          fmt.Sprintf("User Preferred (%s)", methodToString(i.method)),
			Description:   "User's originally selected injection method",
			Method:        i.method,
			BypassOptions: i.bypassOptions,
			Priority:      10,
			Compatibility: []string{"all"},
		})
	}

	// Architecture-specific strategy prioritization
	if archCompat != nil && archCompat.Compatible {
		// Strategy 2: Architecture-optimized Memory Load
		if !i.bypassOptions.MemoryLoad && i.shouldTryMethod(StandardInjection) {
			priority := 9
			description := "Memory-only loading with standard injection"

			// Boost priority for WOW64 processes as memory load works well
			if archCompat.ProcessArch.IsWow64 {
				priority = 10
				description += " (optimized for WOW64)"
			}

			strategies = append(strategies, InjectionStrategy{
				Name:        "Architecture-Optimized Memory Load",
				Description: description,
				Method:      StandardInjection,
				BypassOptions: BypassOptions{
					MemoryLoad:      true,
					ErasePEHeader:   false,
					EraseEntryPoint: false,
					DirectSyscalls:  i.bypassOptions.DirectSyscalls,
				},
				Priority:      priority,
				Compatibility: []string{"architecture-optimized", "stable"},
			})
		}

		// Strategy 3: Architecture-aware Manual Mapping
		if !i.bypassOptions.ManualMapping && i.shouldTryMethod(StandardInjection) {
			priority := 8
			description := "Manual PE mapping without Windows loader"

			// For 64-bit processes, manual mapping often works better
			if archCompat.ProcessArch.Is64Bit && !archCompat.ProcessArch.IsWow64 {
				priority = 9
				description += " (optimized for native 64-bit)"
			}

			strategies = append(strategies, InjectionStrategy{
				Name:        "Architecture-Aware Manual Mapping",
				Description: description,
				Method:      StandardInjection,
				BypassOptions: BypassOptions{
					ManualMapping:   true,
					InvisibleMemory: true,
					DirectSyscalls:  true,
				},
				Priority:      priority,
				Compatibility: []string{"advanced", "stealth", "architecture-aware"},
			})
		}

		// Strategy 4: WOW64-optimized QueueUserAPC (excellent for 32-bit on 64-bit)
		if i.shouldTryMethod(QueueUserAPCInjection) {
			priority := 7
			description := "APC injection with memory loading"
			compatibility := []string{"gui", "threaded"}

			if archCompat.ProcessArch.IsWow64 {
				priority = 8
				description += " (WOW64-optimized)"
				compatibility = append(compatibility, "wow64-optimized")
			}

			strategies = append(strategies, InjectionStrategy{
				Name:        "Architecture-Optimized QueueUserAPC",
				Description: description,
				Method:      QueueUserAPCInjection,
				BypassOptions: BypassOptions{
					MemoryLoad:     true,
					DirectSyscalls: true,
				},
				Priority:      priority,
				Compatibility: compatibility,
			})
		}

		// Strategy 5: SetWindowsHookEx (excellent for WOW64 GUI processes)
		if i.shouldTryMethod(SetWindowsHookExInjection) {
			priority := 6
			description := "Hook-based injection for GUI applications"

			// SetWindowsHookEx works exceptionally well with WOW64 processes
			if archCompat.ProcessArch.IsWow64 {
				priority = 8
				description += " (highly recommended for WOW64)"
			}

			strategies = append(strategies, InjectionStrategy{
				Name:          "WOW64-Optimized SetWindowsHookEx",
				Description:   description,
				Method:        SetWindowsHookExInjection,
				BypassOptions: BypassOptions{
					// No memory load options (incompatible)
				},
				Priority:      priority,
				Compatibility: []string{"gui", "windowed", "wow64-excellent"},
			})
		}
	}

	// Fallback strategies (independent of architecture detection)

	// Strategy 6: Early Bird APC
	if i.shouldTryMethod(EarlyBirdAPCInjection) {
		strategies = append(strategies, InjectionStrategy{
			Name:        "Early Bird APC",
			Description: "APC injection during process initialization",
			Method:      EarlyBirdAPCInjection,
			BypassOptions: BypassOptions{
				MemoryLoad: true,
			},
			Priority:      6,
			Compatibility: []string{"startup", "initialization"},
		})
	}

	// Strategy 7: Standard Injection (universal compatibility)
	if i.shouldTryMethod(StandardInjection) {
		strategies = append(strategies, InjectionStrategy{
			Name:          "Universal Standard Injection",
			Description:   "Basic CreateRemoteThread injection (maximum compatibility)",
			Method:        StandardInjection,
			BypassOptions: BypassOptions{
				// Minimal bypass options for maximum compatibility
			},
			Priority:      5,
			Compatibility: []string{"basic", "compatible", "universal"},
		})
	}

	// Strategy 8: CryoBird (advanced technique)
	if i.shouldTryMethod(CryoBirdInjection) {
		strategies = append(strategies, InjectionStrategy{
			Name:        "CryoBird (Job Object)",
			Description: "Cold injection using job object suspension",
			Method:      CryoBirdInjection,
			BypassOptions: BypassOptions{
				DirectSyscalls: true,
			},
			Priority:      4,
			Compatibility: []string{"advanced", "cold"},
		})
	}

	// Strategy 9: Last resort with automatic recovery
	strategies = append(strategies, InjectionStrategy{
		Name:        "Auto-Recovery Minimal",
		Description: "Standard injection with automatic error recovery (last resort)",
		Method:      StandardInjection,
		BypassOptions: BypassOptions{
			SkipDllMain: true, // Skip problematic DllMain automatically
		},
		Priority:      1,
		Compatibility: []string{"last-resort", "minimal", "auto-recovery"},
	})

	// Sort strategies by priority (higher priority first)
	for i := 0; i < len(strategies)-1; i++ {
		for j := i + 1; j < len(strategies); j++ {
			if strategies[i].Priority < strategies[j].Priority {
				strategies[i], strategies[j] = strategies[j], strategies[i]
			}
		}
	}

	// Log the final strategy order
	i.logger.Info("Built architecture-aware injection strategies", "count", len(strategies))
	for idx, strategy := range strategies {
		i.logger.Debug("Strategy order", "rank", idx+1, "name", strategy.Name,
			"priority", strategy.Priority, "compatibility", strategy.Compatibility)
	}

	return strategies
}

// shouldTryMethod checks if a method should be attempted based on previous failures
func (i *Injector) shouldTryMethod(method InjectionMethod) bool {
	// For now, allow all methods. In a full implementation,
	// you would track failed methods to avoid infinite retries
	return true
}

// executeInjectionStrategy executes a specific injection strategy
func (i *Injector) executeInjectionStrategy(strategy InjectionStrategy, dllBytes []byte) error {
	i.logger.Info("Executing injection strategy", "name", strategy.Name, "method", methodToString(strategy.Method))

	// Handle memory load with bypass options
	if strategy.BypassOptions.MemoryLoad {
		return i.memoryLoadDLL(dllBytes)
	} else if strategy.BypassOptions.ManualMapping {
		// Handle manual mapping
		return i.manualMapDLL(dllBytes)
	} else if strategy.BypassOptions.PathSpoofing {
		// Handle path spoofing
		return i.spoofDLLPath()
	} else if strategy.BypassOptions.LegitProcessInjection {
		// Handle legitimate process injection
		return i.legitProcessInject(dllBytes)
	} else {
		// Standard injection methods
		switch strategy.Method {
		case StandardInjection:
			return i.standardInject()
		case SetWindowsHookExInjection:
			return i.setWindowsHookExInject()
		case QueueUserAPCInjection:
			return i.queueUserAPCInject()
		case EarlyBirdAPCInjection:
			return i.earlyBirdAPCInject()
		case DllNotificationInjection:
			return i.dllNotificationInject()
		case CryoBirdInjection:
			return i.cryoBirdInject()
		default:
			return fmt.Errorf("unsupported injection method: %d", strategy.Method)
		}
	}
}

// shouldContinueRecovery determines if recovery attempts should continue
func (i *Injector) shouldContinueRecovery(err error, attemptIndex, totalAttempts int) bool {
	// Stop if this is the last attempt
	if attemptIndex >= totalAttempts-1 {
		return false
	}

	// Stop on critical errors that affect all methods
	if strings.Contains(err.Error(), "access denied") ||
		strings.Contains(err.Error(), "process not found") ||
		strings.Contains(err.Error(), "target process has exited") {
		i.logger.Info("Stopping recovery due to critical error", "error", err)
		return false
	}

	// Stop if too many attempts (safety limit)
	if attemptIndex >= 5 {
		i.logger.Info("Stopping recovery due to attempt limit", "attempts", attemptIndex+1)
		return false
	}

	return true
}
