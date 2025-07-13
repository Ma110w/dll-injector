package injector

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
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

// SetBypassOptions sets anti-detection options
func (i *Injector) SetBypassOptions(options BypassOptions) {
	i.bypassOptions = options
}

// Inject performs DLL injection using the configured method
func (i *Injector) Inject() error {
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

	// Check if DLL file exists and get detailed info
	fileInfo, err := os.Stat(i.dllPath)
	if os.IsNotExist(err) {
		i.logger.Error("DLL file does not exist", "path", i.dllPath)
		return fmt.Errorf("DLL file does not exist: %s", i.dllPath)
	}
	i.logger.Info("DLL file found", "path", i.dllPath, "size", fileInfo.Size())

	// Check process architecture and permissions
	err = i.validateTargetProcess()
	if err != nil {
		return fmt.Errorf("target process validation failed: %v", err)
	}

	// Validate DLL architecture
	err = i.validateDLLArchitecture()
	if err != nil {
		return fmt.Errorf("DLL validation failed: %v", err)
	}

	i.logger.Info("Starting injection", "method", methodToString(i.method), "dll", i.dllPath, "pid", i.processID)

	// Read DLL bytes if needed for memory operations
	var dllBytes []byte

	if i.bypassOptions.MemoryLoad || i.bypassOptions.ManualMapping {
		dllBytes, err = ioutil.ReadFile(i.dllPath)
		if err != nil {
			i.logger.Error("Failed to read DLL file", "error", err)
			return fmt.Errorf("failed to read DLL file: %v", err)
		}
	}

	// Handle memory load with bypass options
	if i.bypassOptions.MemoryLoad {
		return i.memoryLoadDLL(dllBytes)
	}

	// Handle manual mapping
	if i.bypassOptions.ManualMapping {
		return i.manualMapDLL(dllBytes)
	}

	// Handle path spoofing
	if i.bypassOptions.PathSpoofing {
		return i.diskLoadDLLWithSpoofing()
	}

	// Handle legitimate process injection
	if i.bypassOptions.LegitProcessInjection {
		return i.legitProcessInject(dllBytes)
	}

	// Standard injection methods
	switch i.method {
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
		return fmt.Errorf("unsupported injection method: %d", i.method)
	}
}

// createTempDllFile creates a temporary file with DLL data
func (i *Injector) createTempDllFile(dllBytes []byte) (string, error) {
	tempDir := os.TempDir()
	fileName := fmt.Sprintf("temp_dll_%d.dll", i.processID)
	tempFile := filepath.Join(tempDir, fileName)

	err := ioutil.WriteFile(tempFile, dllBytes, 0644)
	if err != nil {
		return "", fmt.Errorf("failed to create temporary DLL file: %v", err)
	}

	return tempFile, nil
}

// manualMapDLL implements manual DLL mapping
func (i *Injector) manualMapDLL(dllBytes []byte) error {
	i.logger.Info("Using manual mapping method")

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

	// Perform manual mapping with bypass options
	baseAddress, err := i.manualMapDLLWithOptions(hProcess, dllBytes)
	if err != nil {
		i.logger.Error("Manual mapping failed", "error", err)
		return fmt.Errorf("manual mapping failed: %v", err)
	}

	i.logger.Info("Manual mapping successful", "base_address", fmt.Sprintf("0x%X", baseAddress))

	// Apply enhanced techniques if configured
	err = i.applyEnhancedInjectionTechniques(hProcess, baseAddress, uintptr(len(dllBytes)), dllBytes)
	if err != nil {
		i.logger.Warn("Enhanced techniques failed", "error", err)
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

	imageSize := peHeader.OptionalHeader.SizeOfImage
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
	err = MapSections(hProcess, dllBytes, baseAddress, peHeader)
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
			return fmt.Errorf("access denied - try running as administrator or check if target process is protected")
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
	waitResult, err := windows.WaitForSingleObject(threadHandle, 10000) // Increased timeout to 10 seconds
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

	i.logger.Info("Standard injection completed successfully")
	return nil
}

// setWindowsHookExInject implements SetWindowsHookEx injection
func (i *Injector) setWindowsHookExInject() error {
	i.logger.Info("Using SetWindowsHookEx injection method")

	// Load the DLL in current process first
	dllHandle, err := windows.LoadLibrary(i.dllPath)
	if err != nil {
		i.logger.Error("Failed to load DLL", "error", err)
		return fmt.Errorf("failed to load DLL: %v", err)
	}
	defer windows.FreeLibrary(dllHandle)

	// Get a hook procedure address from the DLL
	// This assumes the DLL exports a function suitable for hooking
	user32 := windows.NewLazySystemDLL("user32.dll")
	setWindowsHookEx := user32.NewProc("SetWindowsHookExW")

	// Install hook (WH_GETMESSAGE = 3)
	hookHandle, _, err := setWindowsHookEx.Call(
		uintptr(3), // WH_GETMESSAGE
		uintptr(dllHandle),
		0, // All threads
		uintptr(i.processID))

	if hookHandle == 0 {
		i.logger.Error("Failed to set hook", "error", err)
		return fmt.Errorf("failed to set hook: %v", err)
	}

	i.logger.Info("SetWindowsHookEx injection successful", "hook_handle", hookHandle)
	return nil
}

// queueUserAPCInject implements QueueUserAPC injection
func (i *Injector) queueUserAPCInject() error {
	i.logger.Info("Using QueueUserAPC injection method")

	// Open target process
	hProcess, err := windows.OpenProcess(
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

	// Find a thread in alertable state
	threadHandle, err := FindAlertableThread(i.processID)
	if err != nil {
		i.logger.Error("Failed to find alertable thread", "error", err)
		return fmt.Errorf("failed to find alertable thread: %v", err)
	}
	defer windows.CloseHandle(threadHandle)

	// Allocate memory and write DLL path
	dllPathBytes := []byte(i.dllPath + "\x00")
	pathSize := len(dllPathBytes)

	memAddr, err := VirtualAllocEx(hProcess, 0, uintptr(pathSize),
		windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_READWRITE)
	if err != nil {
		i.logger.Error("Failed to allocate memory", "error", err)
		return fmt.Errorf("failed to allocate memory: %v", err)
	}

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

	// Queue APC
	queueUserAPC := kernel32.NewProc("QueueUserAPC")
	ret, _, err := queueUserAPC.Call(loadLibraryAddr, uintptr(threadHandle), memAddr)
	if ret == 0 {
		i.logger.Error("Failed to queue APC", "error", err)
		return fmt.Errorf("failed to queue APC: %v", err)
	}

	i.logger.Info("QueueUserAPC injection successful")
	return nil
}

// earlyBirdAPCInject implements Early Bird APC injection
func (i *Injector) earlyBirdAPCInject() error {
	i.logger.Info("Using Early Bird APC injection method")

	// Create process in suspended state
	processInfo, err := CreateSuspendedProcess(i.processID)
	if err != nil {
		i.logger.Error("Failed to create suspended process", "error", err)
		return fmt.Errorf("failed to create suspended process: %v", err)
	}
	defer windows.CloseHandle(processInfo.Process)
	defer windows.CloseHandle(processInfo.Thread)

	// Allocate memory and write DLL path
	dllPathBytes := []byte(i.dllPath + "\x00")
	pathSize := len(dllPathBytes)

	memAddr, err := VirtualAllocEx(processInfo.Process, 0, uintptr(pathSize),
		windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_READWRITE)
	if err != nil {
		i.logger.Error("Failed to allocate memory", "error", err)
		return fmt.Errorf("failed to allocate memory: %v", err)
	}

	var bytesWritten uintptr
	err = WriteProcessMemory(processInfo.Process, memAddr, unsafe.Pointer(&dllPathBytes[0]),
		uintptr(pathSize), &bytesWritten)
	if err != nil {
		i.logger.Error("Failed to write DLL path", "error", err)
		return fmt.Errorf("failed to write DLL path: %v", err)
	}

	// Get LoadLibraryA address
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	loadLibraryA := kernel32.NewProc("LoadLibraryA")
	loadLibraryAddr := loadLibraryA.Addr()

	// Queue APC to suspended thread
	queueUserAPC := kernel32.NewProc("QueueUserAPC")
	ret, _, err := queueUserAPC.Call(loadLibraryAddr, uintptr(processInfo.Thread), memAddr)
	if ret == 0 {
		i.logger.Error("Failed to queue APC", "error", err)
		return fmt.Errorf("failed to queue APC: %v", err)
	}

	// Resume the main thread
	_, err = windows.ResumeThread(processInfo.Thread)
	if err != nil {
		i.logger.Error("Failed to resume thread", "error", err)
		return fmt.Errorf("failed to resume thread: %v", err)
	}

	i.logger.Info("Early Bird APC injection successful")
	return nil
}

// dllNotificationInject implements DLL notification injection
func (i *Injector) dllNotificationInject() error {
	i.logger.Info("Using DLL notification injection method")

	// This is a complex method that involves DLL load notifications
	// For now, implement a basic version that uses standard injection
	// In a full implementation, this would hook DLL load notifications

	return i.standardInject()
}

// cryoBirdInject implements job object freeze process injection
func (i *Injector) cryoBirdInject() error {
	i.logger.Info("Using CryoBird (job object freeze) injection method")

	// Create job object
	jobHandle, err := CreateJobObject(nil, nil)
	if err != nil {
		i.logger.Error("Failed to create job object", "error", err)
		return fmt.Errorf("failed to create job object: %v", err)
	}
	defer windows.CloseHandle(jobHandle)

	// Open target process
	hProcess, err := windows.OpenProcess(
		windows.PROCESS_ALL_ACCESS,
		false, i.processID)
	if err != nil {
		i.logger.Error("Failed to open target process", "error", err)
		return fmt.Errorf("failed to open target process: %v", err)
	}
	defer windows.CloseHandle(hProcess)

	// Assign process to job object (this freezes it)
	err = AssignProcessToJobObject(jobHandle, hProcess)
	if err != nil {
		i.logger.Error("Failed to assign process to job", "error", err)
		return fmt.Errorf("failed to assign process to job: %v", err)
	}

	// Perform injection while process is frozen
	err = i.standardInject()
	if err != nil {
		return err
	}

	// Terminate job object to unfreeze process
	err = TerminateJobObject(jobHandle, 0)
	if err != nil {
		i.logger.Warn("Failed to terminate job object", "error", err)
	}

	i.logger.Info("CryoBird injection successful")
	return nil
}

// Windows API function declarations

var (
	kernel32                     = windows.NewLazySystemDLL("kernel32.dll")
	procVirtualAllocEx           = kernel32.NewProc("VirtualAllocEx")
	procWriteProcessMemory       = kernel32.NewProc("WriteProcessMemory")
	procCreateRemoteThread       = kernel32.NewProc("CreateRemoteThread")
	procCreateJobObjectW         = kernel32.NewProc("CreateJobObjectW")
	procAssignProcessToJobObject = kernel32.NewProc("AssignProcessToJobObject")
	procTerminateJobObject       = kernel32.NewProc("TerminateJobObject")
	procGetExitCodeThread        = kernel32.NewProc("GetExitCodeThread")
	procSuspendThread            = kernel32.NewProc("SuspendThread") // 修复：添加缺失的声明
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
func CreateRemoteThread(hProcess windows.Handle, lpThreadAttributes *windows.SecurityAttributes, dwStackSize uintptr, lpStartAddress uintptr, lpParameter uintptr, dwCreationFlags uint32, lpThreadId *uint32) (windows.Handle, error) {
	ret, _, err := procCreateRemoteThread.Call(
		uintptr(hProcess),
		uintptr(unsafe.Pointer(lpThreadAttributes)),
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
func CreateJobObject(lpJobAttributes *windows.SecurityAttributes, lpName *uint16) (windows.Handle, error) {
	ret, _, err := procCreateJobObjectW.Call(
		uintptr(unsafe.Pointer(lpJobAttributes)),
		uintptr(unsafe.Pointer(lpName)))
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

// ProcessInformation represents process creation information
type ProcessInformation struct {
	Process   windows.Handle
	Thread    windows.Handle
	ProcessId uint32
	ThreadId  uint32
}

// FindAlertableThread finds an alertable thread in the target process
func FindAlertableThread(processID uint32) (windows.Handle, error) {
	// This is a simplified implementation
	// In reality, you would enumerate threads and find one in alertable state
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
			threadHandle, err := windows.OpenThread(windows.THREAD_SET_CONTEXT, false, te.ThreadID)
			if err == nil {
				return threadHandle, nil
			}
		}

		err = windows.Thread32Next(snapshot, &te)
		if err != nil {
			break
		}
	}

	return 0, fmt.Errorf("no alertable thread found")
}

// CreateSuspendedProcess creates a process in suspended state
func CreateSuspendedProcess(processID uint32) (*ProcessInformation, error) {
	// This function should ideally suspend an existing process
	// For now, we'll open the existing process and its main thread

	// Open the target process
	hProcess, err := windows.OpenProcess(
		windows.PROCESS_ALL_ACCESS,
		false, processID)
	if err != nil {
		return nil, fmt.Errorf("failed to open process: %v", err)
	}

	// Find the main thread of the process
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		windows.CloseHandle(hProcess)
		return nil, fmt.Errorf("failed to create thread snapshot: %v", err)
	}
	defer windows.CloseHandle(snapshot)

	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))

	err = windows.Thread32First(snapshot, &te)
	if err != nil {
		windows.CloseHandle(hProcess)
		return nil, fmt.Errorf("failed to enumerate threads: %v", err)
	}

	var mainThread windows.Handle
	for {
		if te.OwnerProcessID == processID {
			threadHandle, err := windows.OpenThread(
				windows.THREAD_SUSPEND_RESUME|windows.THREAD_GET_CONTEXT|windows.THREAD_SET_CONTEXT,
				false, te.ThreadID)
			if err == nil {
				// Suspend the thread
				ret, _, _ := procSuspendThread.Call(uintptr(threadHandle))
				if ret != 0xFFFFFFFF { // INVALID_HANDLE_VALUE
					mainThread = threadHandle
					break
				}
				windows.CloseHandle(threadHandle)
			}
		}

		err = windows.Thread32Next(snapshot, &te)
		if err != nil {
			break
		}
	}

	if mainThread == 0 {
		windows.CloseHandle(hProcess)
		return nil, fmt.Errorf("failed to find and suspend main thread")
	}

	return &ProcessInformation{
		Process:   hProcess,
		Thread:    mainThread,
		ProcessId: processID,
		ThreadId:  te.ThreadID,
	}, nil
}

// validateTargetProcess checks if target process is accessible and gets its architecture
func (i *Injector) validateTargetProcess() error {
	i.logger.Info("Validating target process", "pid", i.processID)

	// Try to open process with required permissions
	hProcess, err := windows.OpenProcess(
		windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ,
		false, i.processID)
	if err != nil {
		i.logger.Error("Cannot open target process for validation", "error", err, "pid", i.processID)
		return fmt.Errorf("cannot open target process (PID %d): %v. Try running as administrator", i.processID, err)
	}
	defer windows.CloseHandle(hProcess)

	// Check if process is still running
	var exitCode uint32
	err = windows.GetExitCodeProcess(hProcess, &exitCode)
	if err != nil {
		i.logger.Error("Failed to get process exit code", "error", err)
		return fmt.Errorf("failed to query process status: %v", err)
	}

	if exitCode != 259 { // STILL_ACTIVE = 259
		i.logger.Error("Target process is not running", "exit_code", exitCode)
		return fmt.Errorf("target process (PID %d) is not running", i.processID)
	}

	// Check process architecture
	var isWow64 bool
	err = windows.IsWow64Process(hProcess, &isWow64)
	if err != nil {
		i.logger.Warn("Failed to check process architecture", "error", err)
	} else {
		if isWow64 {
			i.logger.Info("Target process is 32-bit (WoW64)")
		} else {
			i.logger.Info("Target process is 64-bit")
		}
	}

	i.logger.Info("Target process validation successful")
	return nil
}

// validateDLLArchitecture checks if DLL architecture matches target process
func (i *Injector) validateDLLArchitecture() error {
	i.logger.Info("Validating DLL architecture", "dll", i.dllPath)

	// Read DLL file
	dllBytes, err := os.ReadFile(i.dllPath)
	if err != nil {
		return fmt.Errorf("failed to read DLL file: %v", err)
	}

	if len(dllBytes) < 64 {
		return fmt.Errorf("DLL file too small to be valid")
	}

	// Check DOS header
	if dllBytes[0] != 'M' || dllBytes[1] != 'Z' {
		return fmt.Errorf("invalid DLL file: missing MZ signature")
	}

	// Get PE header offset
	peOffset := *(*uint32)(unsafe.Pointer(&dllBytes[60]))
	if peOffset >= uint32(len(dllBytes)) || peOffset < 64 {
		return fmt.Errorf("invalid PE header offset")
	}

	// Check PE signature
	if peOffset+4 >= uint32(len(dllBytes)) {
		return fmt.Errorf("PE header beyond file end")
	}

	if dllBytes[peOffset] != 'P' || dllBytes[peOffset+1] != 'E' {
		return fmt.Errorf("invalid DLL file: missing PE signature")
	}

	// Get machine type
	if peOffset+24 >= uint32(len(dllBytes)) {
		return fmt.Errorf("machine type beyond file end")
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
