package injector

import (
	"encoding/binary"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// memoryLoadDLL implements true memory-only DLL loading using reflective loading
func (i *Injector) memoryLoadDLL(dllBytes []byte) error {
	i.logger.Info("Using true memory load method")

	// Validate DLL bytes
	if len(dllBytes) == 0 {
		return fmt.Errorf("DLL bytes cannot be empty")
	}

	// Add additional validation for common corruption issues
	if len(dllBytes) < 1024 {
		return fmt.Errorf("DLL file too small: %d bytes (minimum 1024 expected)", len(dllBytes))
	}

	// Validate DOS signature before parsing
	if dllBytes[0] != 'M' || dllBytes[1] != 'Z' {
		i.logger.Error("Invalid DOS signature detected",
			"first_bytes", fmt.Sprintf("%02x %02x", dllBytes[0], dllBytes[1]))
		return fmt.Errorf("invalid DOS signature: expected 'MZ', got '%c%c' (0x%02x%02x)",
			dllBytes[0], dllBytes[1], dllBytes[0], dllBytes[1])
	}

	// Parse PE header to validate and get required information
	peHeader, err := ParsePEHeader(dllBytes)
	if err != nil {
		i.logger.Error("PE header parsing failed", "error", err, "dll_size", len(dllBytes))

		// Try to provide more helpful debugging information
		if len(dllBytes) >= 64 {
			peOffset := binary.LittleEndian.Uint32(dllBytes[60:64])
			i.logger.Error("PE parsing debug info",
				"pe_offset", peOffset,
				"dos_signature", fmt.Sprintf("%02x %02x", dllBytes[0], dllBytes[1]),
				"file_size", len(dllBytes))
		}

		return fmt.Errorf("failed to parse PE header for memory load: %v", err)
	}

	// Validate the parsed PE header
	if err := peHeader.ValidateArchitecture(); err != nil {
		return fmt.Errorf("architecture validation failed: %v", err)
	}

	// Additional validation for memory loading
	imageSize := peHeader.GetSizeOfImage()
	if imageSize == 0 {
		return fmt.Errorf("invalid image size: 0")
	}
	if imageSize > 0x10000000 { // 256MB sanity check
		return fmt.Errorf("image size too large: %d bytes", imageSize)
	}

	i.logger.Info("PE header validation successful",
		"architecture", map[bool]string{true: "64-bit", false: "32-bit"}[peHeader.Is64Bit],
		"image_size", imageSize)

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

	// Method 1: Use reflective DLL loading technique
	if err := i.reflectiveMemoryLoad(hProcess, dllBytes, peHeader); err == nil {
		i.logger.Info("Reflective memory loading successful")
		return nil
	} else {
		i.logger.Warn("Reflective loading failed, trying fallback method", "error", err)
	}

	// Method 2: Fallback to enhanced temporary file approach with anti-detection
	return i.enhancedTempFileLoad(hProcess, dllBytes)
}

// reflectiveMemoryLoad implements memory-only DLL loading using manual mapping
func (i *Injector) reflectiveMemoryLoad(hProcess windows.Handle, dllBytes []byte, peHeader *PEHeader) error {
	i.logger.Info("Attempting memory-only DLL loading using manual mapping")

	// Additional safety checks
	if peHeader == nil {
		return fmt.Errorf("PE header is nil")
	}

	// Allocate memory in target process for the entire DLL
	imageSize := peHeader.GetSizeOfImage()
	if imageSize == 0 {
		return fmt.Errorf("invalid image size from PE header: 0")
	}

	// Sanity check for image size
	if imageSize > 0x10000000 { // 256MB
		return fmt.Errorf("image size too large: %d bytes", imageSize)
	}

	i.logger.Info("Allocating memory for DLL", "size", imageSize)

	// Use high address space for stealth
	var baseAddress uintptr
	var err error
	if i.bypassOptions.InvisibleMemory {
		baseAddress, err = InvisibleMemoryAllocation(hProcess, uintptr(imageSize))
		if err != nil {
			i.logger.Warn("Invisible memory allocation failed, falling back to standard allocation", "error", err)
			baseAddress, err = VirtualAllocEx(hProcess, 0, uintptr(imageSize),
				windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
			if err != nil {
				return fmt.Errorf("fallback memory allocation failed: %v", err)
			}
		} else {
			i.logger.Info("Allocated invisible memory", "address", fmt.Sprintf("0x%X", baseAddress), "size", imageSize)
		}
	} else {
		baseAddress, err = VirtualAllocEx(hProcess, 0, uintptr(imageSize),
			windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
		if err != nil {
			return fmt.Errorf("failed to allocate memory: %v", err)
		}
		i.logger.Info("Allocated standard memory", "address", fmt.Sprintf("0x%X", baseAddress), "size", imageSize)
	}

	// Ensure cleanup on failure
	defer func() {
		if err != nil {
			if freeErr := VirtualFreeEx(hProcess, baseAddress, 0, windows.MEM_RELEASE); freeErr != nil {
				i.logger.Warn("Failed to free allocated memory during cleanup", "error", freeErr)
			}
		}
	}()

	// Perform manual mapping of PE sections
	i.logger.Info("Mapping PE sections to target memory")
	err = MapSections(hProcess, dllBytes, baseAddress, peHeader)
	if err != nil {
		return fmt.Errorf("failed to map PE sections: %v", err)
	}

	// Temporarily set all memory to RWX for relocation processing
	i.logger.Info("Setting temporary memory permissions for relocation processing")
	var oldProtect uint32
	err = windows.VirtualProtectEx(hProcess, baseAddress, uintptr(peHeader.GetSizeOfImage()),
		windows.PAGE_EXECUTE_READWRITE, &oldProtect)
	if err != nil {
		i.logger.Warn("Failed to set temporary memory permissions", "error", err)
	}

	// Process relocations
	i.logger.Info("Processing relocations")
	err = FixRelocations(hProcess, baseAddress, peHeader)
	if err != nil {
		i.logger.Warn("Failed to process relocations", "error", err)
		// Continue anyway as some DLLs might work without relocations
	}

	// Restore proper section permissions after relocation
	i.logger.Info("Restoring proper section permissions")
	err = i.restoreSectionPermissions(hProcess, baseAddress, peHeader)
	if err != nil {
		i.logger.Warn("Failed to restore section permissions", "error", err)
	}

	// Resolve imports
	i.logger.Info("Resolving imports")
	err = FixImports(hProcess, baseAddress, peHeader)
	if err != nil {
		i.logger.Warn("Failed to resolve imports", "error", err)
		// Continue anyway - some DLLs might work with partial imports
	}

	// Get entry point and execute DLL
	entryPointRVA := peHeader.GetAddressOfEntryPoint()
	if entryPointRVA != 0 {
		entryPointAddr := baseAddress + uintptr(entryPointRVA)
		i.logger.Info("Executing DLL entry point", "entry_point", fmt.Sprintf("0x%X", entryPointAddr))

		// Create remote thread to execute DLL entry point
		// DLL entry point signature: BOOL DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
		// We'll call it with DLL_PROCESS_ATTACH (1)
		var threadID uint32
		threadHandle, err := CreateRemoteThread(hProcess, nil, 0,
			entryPointAddr, baseAddress, 0, &threadID)
		if err != nil {
			return fmt.Errorf("failed to create entry point thread: %v", err)
		}
		defer windows.CloseHandle(threadHandle)

		i.logger.Info("Created entry point thread", "thread_id", threadID)

		// Wait for entry point execution to complete
		waitResult, err := windows.WaitForSingleObject(threadHandle, 10000) // 10 seconds
		if err != nil {
			return fmt.Errorf("failed to wait for entry point: %v", err)
		}

		if waitResult == uint32(windows.WAIT_TIMEOUT) {
			i.logger.Warn("Entry point execution timed out")
			// Don't fail here, the DLL might still be loaded
		} else {
			// Get the result
			var exitCode uint32
			ret, _, _ := procGetExitCodeThread.Call(uintptr(threadHandle), uintptr(unsafe.Pointer(&exitCode)))
			if ret != 0 {
				i.logger.Info("Entry point execution completed", "exit_code", exitCode)
			}
		}
	} else {
		i.logger.Info("No entry point found, DLL loaded without initialization")
	}

	i.logger.Info("Memory-only DLL loading completed", "dll_base", fmt.Sprintf("0x%X", baseAddress))

	// Apply post-loading anti-detection techniques
	return i.applyPostLoadingTechniques(hProcess, baseAddress, dllBytes)
}

// enhancedTempFileLoad implements enhanced temporary file loading with anti-detection
func (i *Injector) enhancedTempFileLoad(hProcess windows.Handle, dllBytes []byte) error {
	i.logger.Info("Using enhanced temporary file loading")

	// Create temporary file in a less suspicious location
	tempFile, err := i.createStealthTempFile(dllBytes)
	if err != nil {
		return fmt.Errorf("failed to create stealth temp file: %v", err)
	}

	// Schedule file deletion
	defer func() {
		// Use multiple deletion attempts for better cleanup
		for attempts := 0; attempts < 3; attempts++ {
			if err := os.Remove(tempFile); err == nil {
				i.logger.Info("Temporary file cleaned up", "file", tempFile)
				break
			}
			if attempts == 2 {
				i.logger.Warn("Failed to clean up temporary file", "file", tempFile)
			}
		}
	}()

	// Allocate memory for DLL path
	dllPathBytes := []byte(tempFile + "\x00")
	pathSize := len(dllPathBytes)

	memAddr, err := VirtualAllocEx(hProcess, 0, uintptr(pathSize),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return fmt.Errorf("failed to allocate path memory: %v", err)
	}

	// Write DLL path
	var bytesWritten uintptr
	err = WriteProcessMemory(hProcess, memAddr, unsafe.Pointer(&dllPathBytes[0]),
		uintptr(pathSize), &bytesWritten)
	if err != nil {
		return fmt.Errorf("failed to write DLL path: %v", err)
	}

	// Get LoadLibrary address using direct function resolution
	loadLibraryAddr, err := i.resolveLoadLibraryAddress()
	if err != nil {
		return fmt.Errorf("failed to resolve LoadLibrary address: %v", err)
	}

	// Create remote thread to load the DLL
	var threadID uint32
	threadHandle, err := CreateRemoteThread(hProcess, nil, 0, loadLibraryAddr, memAddr, 0, &threadID)
	if err != nil {
		return fmt.Errorf("failed to create remote thread: %v", err)
	}
	defer windows.CloseHandle(threadHandle)

	// Wait for loading to complete
	waitResult, err := windows.WaitForSingleObject(threadHandle, 10000)
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
	i.logger.Info("DLL loaded successfully", "base_address", fmt.Sprintf("0x%X", dllBaseAddress))

	// Apply post-loading anti-detection techniques
	return i.applyPostLoadingTechniques(hProcess, dllBaseAddress, dllBytes)
}

// createStealthTempFile creates a temporary file in a less suspicious location
func (i *Injector) createStealthTempFile(dllBytes []byte) (string, error) {
	// Try various locations in order of preference
	locations := []string{
		os.Getenv("APPDATA"),
		os.Getenv("LOCALAPPDATA"),
		os.Getenv("TEMP"),
		os.TempDir(),
	}

	// Use real system DLL names for stealth
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
	filename := realDllNames[i.processID%uint32(len(realDllNames))]

	for _, location := range locations {
		if location == "" {
			continue
		}

		tempFile := location + "\\" + filename
		if err := os.WriteFile(tempFile, dllBytes, 0644); err == nil {
			i.logger.Info("Created stealth temp file", "location", tempFile)
			return tempFile, nil
		}
	}

	return "", fmt.Errorf("failed to create temp file in any location")
}

// applyPostLoadingTechniques applies anti-detection techniques after DLL loading
func (i *Injector) applyPostLoadingTechniques(hProcess windows.Handle, dllBase uintptr, dllBytes []byte) error {
	i.logger.Info("Applying post-loading anti-detection techniques")

	// Erase PE header if requested
	if i.bypassOptions.ErasePEHeader {
		if err := ErasePEHeader(hProcess, dllBase); err != nil {
			i.logger.Warn("Failed to erase PE header", "error", err)
		} else {
			i.logger.Info("PE header erased successfully")
		}
	}

	// Erase entry point if requested
	if i.bypassOptions.EraseEntryPoint {
		if err := EraseEntryPoint(hProcess, dllBase); err != nil {
			i.logger.Warn("Failed to erase entry point", "error", err)
		} else {
			i.logger.Info("Entry point erased successfully")
		}
	}

	// Apply advanced bypass options
	if err := ApplyAdvancedBypassOptions(hProcess, dllBase, uintptr(len(dllBytes)), i.bypassOptions); err != nil {
		i.logger.Warn("Failed to apply advanced bypass options", "error", err)
	}

	return nil
}

// createReflectiveLoaderStub creates a simple loader stub for manual mapping
func (i *Injector) createReflectiveLoaderStub(dllBytes []byte, targetBase uintptr) ([]byte, error) {
	i.logger.Info("Creating manual mapping loader stub")

	// Since we're using manual mapping approach, we just need a simple stub
	// that returns the base address to indicate success
	// The actual mapping is done by the Go code before calling this stub

	// Simple x64 stub that returns the DLL base address
	stub := []byte{
		0x48, 0x83, 0xEC, 0x28, // sub rsp, 0x28 (shadow space)
		0x48, 0x8B, 0xC1, // mov rax, rcx (DLL base address parameter)
		0x48, 0x85, 0xC0, // test rax, rax (check if base is valid)
		0x74, 0x02, // jz error_exit (if base is 0)
		0xEB, 0x02, // jmp success_exit
		// error_exit:
		0x33, 0xC0, // xor eax, eax (return 0 for failure)
		// success_exit:
		0x48, 0x83, 0xC4, 0x28, // add rsp, 0x28
		0xC3, // ret
	}

	i.logger.Info("Created manual mapping loader stub", "stub_size", len(stub))
	return stub, nil
}

// restoreSectionPermissions restores proper memory permissions for each PE section
func (i *Injector) restoreSectionPermissions(hProcess windows.Handle, baseAddress uintptr, peHeader *PEHeader) error {
	i.logger.Info("Restoring section permissions")

	for _, section := range peHeader.SectionHeaders {
		sectionName := string(section.Name[:])
		if nullIndex := findNull(sectionName); nullIndex != -1 {
			sectionName = sectionName[:nullIndex]
		}

		// Skip empty sections
		if section.VirtualSize == 0 && section.SizeOfRawData == 0 {
			continue
		}

		targetAddr := baseAddress + uintptr(section.VirtualAddress)
		sectionSize := section.VirtualSize
		if sectionSize == 0 {
			sectionSize = section.SizeOfRawData
		}

		// Calculate appropriate protection based on section characteristics
		var newProtect uint32
		if section.Characteristics&IMAGE_SCN_MEM_EXECUTE != 0 {
			if section.Characteristics&IMAGE_SCN_MEM_WRITE != 0 {
				newProtect = windows.PAGE_EXECUTE_READWRITE
			} else {
				newProtect = windows.PAGE_EXECUTE_READ
			}
		} else if section.Characteristics&IMAGE_SCN_MEM_WRITE != 0 {
			newProtect = windows.PAGE_READWRITE
		} else {
			newProtect = windows.PAGE_READONLY
		}

		// Apply the protection
		var oldProtect uint32
		err := windows.VirtualProtectEx(hProcess, targetAddr, uintptr(sectionSize), newProtect, &oldProtect)
		if err != nil {
			i.logger.Warn("Failed to restore protection for section", "section", sectionName, "error", err)
			continue
		}

		i.logger.Debug("Restored section permissions", "section", sectionName, "protection", fmt.Sprintf("0x%X", newProtect))
	}

	return nil
}
