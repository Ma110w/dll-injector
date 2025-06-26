package injector

import (
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"unsafe"
)

// memoryLoadDLL loads DLL from memory by creating a temporary file
func (i *Injector) memoryLoadDLL(dllBytes []byte) error {
	i.logger.Info("Using memory load method")

	// 创建临时文件来存储DLL数据
	tempFile, err := i.createTempDllFile(dllBytes)
	if err != nil {
		i.logger.Error("Memory load failed", "error", err)
		return err
	}
	defer func() {
		// 清理临时文件
		if removeErr := os.Remove(tempFile); removeErr != nil {
			i.logger.Warn("Failed to remove temporary DLL file", "file", tempFile, "error", removeErr)
		} else {
			i.logger.Info("Temporary DLL file removed", "file", tempFile)
		}
	}()

	i.logger.Info("Created temporary DLL file", "file", tempFile)

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
		i.logger.Error("Memory load failed", "error", newErr)
		return newErr
	}
	defer windows.CloseHandle(hProcess)

	i.logger.Info("Successfully opened target process")

	// 将临时文件路径写入目标进程内存
	dllPathBytes := []byte(tempFile + "\x00") // 添加null终止符
	pathSize := len(dllPathBytes)

	// 分配内存存储DLL路径
	var memFlags uint32 = windows.MEM_RESERVE | windows.MEM_COMMIT
	var memProt uint32 = windows.PAGE_READWRITE

	memAddr, err := VirtualAllocEx(hProcess, 0, uintptr(pathSize),
		memFlags, memProt)
	if err != nil {
		errMsg := "Failed to allocate memory: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Memory load failed", "error", newErr)
		return newErr
	}

	// 写入DLL路径
	var bytesWritten uintptr
	err = WriteProcessMemory(hProcess, memAddr, unsafe.Pointer(&dllPathBytes[0]),
		uintptr(pathSize), &bytesWritten)
	if err != nil {
		errMsg := "Failed to write DLL path to memory: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Memory load failed", "error", newErr)
		return newErr
	}

	// 获取LoadLibraryA地址
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	loadLibraryA := kernel32.NewProc("LoadLibraryA")
	loadLibraryAddr := loadLibraryA.Addr()

	// 创建远程线程执行LoadLibraryA
	var threadID uint32
	threadHandle, err := CreateRemoteThread(hProcess, nil, 0,
		loadLibraryAddr, memAddr, 0, &threadID)
	if err != nil {
		errMsg := "Failed to create remote thread: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Memory load failed", "error", newErr)
		return newErr
	}
	defer windows.CloseHandle(threadHandle)

	i.logger.Info("Successfully created remote thread", "thread_id", threadID)

	// 等待线程完成
	waitResult, err := windows.WaitForSingleObject(threadHandle, 5000) // 等待5秒
	if err != nil {
		i.logger.Warn("Failed to wait for remote thread", "error", err)
	} else if waitResult == uint32(windows.WAIT_TIMEOUT) {
		i.logger.Warn("Remote thread execution timed out")
	} else {
		i.logger.Info("Remote thread completed successfully")
	}

	// 应用反检测技术
	if i.bypassOptions.ErasePEHeader {
		i.logger.Info("Erasing PE header for stealth")
		err = ErasePEHeader(hProcess, memAddr)
		if err != nil {
			i.logger.Warn("Failed to erase PE header", "error", err)
			// 不返回错误，因为这不是关键操作
		}
	}

	if i.bypassOptions.EraseEntryPoint {
		i.logger.Info("Erasing entry point for stealth")
		err = EraseEntryPoint(hProcess, memAddr)
		if err != nil {
			i.logger.Warn("Failed to erase entry point", "error", err)
			// 不返回错误，因为这不是关键操作
		}
	}

	// 应用高级反检测技术
	dllSize := len(dllBytes)
	err = ApplyAdvancedBypassOptions(hProcess, memAddr, uintptr(dllSize), i.bypassOptions)
	if err != nil {
		i.logger.Warn("Failed to apply advanced bypass options", "error", err)
		// 不返回错误，因为这不是关键操作
	}

	return nil
}

// Note: manualMapDLL and legitProcessInject methods are defined in injector.go to avoid duplicate declarations
