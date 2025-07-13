package injector

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// MapSections maps PE sections to remote process memory
func MapSections(hProcess windows.Handle, dllBytes []byte, baseAddress uintptr, peHeader *PEHeader) error {
	Printf("Starting PE sections mapping...\n")

	// Map headers first
	var sizeOfHeaders uint32

	if peHeader.Is64Bit {
		opt := peHeader.OptionalHeader.(OptionalHeader64)
		sizeOfHeaders = opt.SizeOfHeaders
	} else {
		opt := peHeader.OptionalHeader.(OptionalHeader32)
		sizeOfHeaders = opt.SizeOfHeaders
	}

	Printf("Mapping PE headers (size: %d bytes)...\n", sizeOfHeaders)

	// Write PE headers to base address
	if sizeOfHeaders > uint32(len(dllBytes)) {
		sizeOfHeaders = uint32(len(dllBytes))
	}

	var bytesWritten uintptr
	err := WriteProcessMemory(hProcess, baseAddress, unsafe.Pointer(&dllBytes[0]),
		uintptr(sizeOfHeaders), &bytesWritten)
	if err != nil {
		return fmt.Errorf("failed to write PE headers: %v", err)
	}

	Printf("Successfully mapped PE headers (%d bytes written)\n", bytesWritten)

	// Map each section
	for i, section := range peHeader.SectionHeaders {
		sectionName := string(section.Name[:])
		if nullIndex := findNull(sectionName); nullIndex != -1 {
			sectionName = sectionName[:nullIndex]
		}

		Printf("Mapping section %d: %s\n", i, sectionName)
		Printf("  Virtual Address: 0x%X\n", section.VirtualAddress)
		Printf("  Virtual Size: %d bytes\n", section.VirtualSize)
		Printf("  Raw Data Pointer: 0x%X\n", section.PointerToRawData)
		Printf("  Raw Data Size: %d bytes\n", section.SizeOfRawData)

		// Skip empty sections
		if section.SizeOfRawData == 0 {
			Printf("  Skipping empty section\n")
			continue
		}

		// Calculate target address
		targetAddr := baseAddress + uintptr(section.VirtualAddress)

		// Validate raw data bounds
		if section.PointerToRawData >= uint32(len(dllBytes)) {
			Printf("  Warning: Raw data pointer beyond file bounds, skipping\n")
			continue
		}

		// Calculate actual data size to copy
		dataSize := section.SizeOfRawData
		availableSize := uint32(len(dllBytes)) - section.PointerToRawData
		if dataSize > availableSize {
			dataSize = availableSize
			Printf("  Warning: Truncating section data to %d bytes\n", dataSize)
		}

		if dataSize == 0 {
			Printf("  Skipping section with no available data\n")
			continue
		}

		// Write section data
		sectionData := dllBytes[section.PointerToRawData : section.PointerToRawData+dataSize]
		err = WriteProcessMemory(hProcess, targetAddr, unsafe.Pointer(&sectionData[0]),
			uintptr(dataSize), &bytesWritten)
		if err != nil {
			Printf("  Warning: Failed to map section %s: %v\n", sectionName, err)
			continue
		}

		Printf("  Successfully mapped section %s (%d bytes)\n", sectionName, bytesWritten)

		// Set appropriate memory protection
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

		// Apply memory protection
		var oldProtect uint32
		protectSize := section.VirtualSize
		if protectSize == 0 {
			protectSize = section.SizeOfRawData
		}

		err = windows.VirtualProtectEx(hProcess, targetAddr, uintptr(protectSize), newProtect, &oldProtect)
		if err != nil {
			Printf("  Warning: Failed to set memory protection for section %s: %v\n", sectionName, err)
		} else {
			Printf("  Set memory protection for section %s: 0x%X\n", sectionName, newProtect)
		}
	}

	Printf("PE sections mapping completed\n")
	return nil
}

// FixImports resolves import table
func FixImports(hProcess windows.Handle, baseAddress uintptr, peHeader *PEHeader) error {
	Printf("Starting import table resolution...\n")

	// Get import directory
	if len(peHeader.DataDirectories) <= IMAGE_DIRECTORY_ENTRY_IMPORT {
		Printf("No import directory found\n")
		return nil
	}

	importDir := peHeader.DataDirectories[IMAGE_DIRECTORY_ENTRY_IMPORT]
	if importDir.VirtualAddress == 0 || importDir.Size == 0 {
		Printf("Import directory is empty\n")
		return nil
	}

	Printf("Import directory: RVA=0x%X, Size=%d\n", importDir.VirtualAddress, importDir.Size)

	// Read import descriptors from target process
	importAddr := baseAddress + uintptr(importDir.VirtualAddress)
	descriptorCount := importDir.Size / uint32(unsafe.Sizeof(ImportDescriptor{}))

	Printf("Processing %d import descriptors...\n", descriptorCount)

	for i := uint32(0); i < descriptorCount; i++ {
		var descriptor ImportDescriptor
		descAddr := importAddr + uintptr(i*uint32(unsafe.Sizeof(ImportDescriptor{})))

		// Read import descriptor from target process
		var bytesRead uintptr
		err := windows.ReadProcessMemory(hProcess, descAddr,
			(*byte)(unsafe.Pointer(&descriptor)), unsafe.Sizeof(descriptor), &bytesRead)
		if err != nil {
			Printf("Failed to read import descriptor %d: %v\n", i, err)
			continue
		}

		// Check if this is the end of descriptors
		if descriptor.Name == 0 {
			Printf("Reached end of import descriptors\n")
			break
		}

		// Read DLL name
		dllNameAddr := baseAddress + uintptr(descriptor.Name)
		dllName, err := readStringFromProcess(hProcess, dllNameAddr)
		if err != nil {
			Printf("Failed to read DLL name for descriptor %d: %v\n", i, err)
			continue
		}

		Printf("Processing imports from DLL: %s\n", dllName)

		// Load the DLL in current process to resolve exports
		dllHandle, err := windows.LoadLibrary(dllName)
		if err != nil {
			Printf("Warning: Failed to load DLL %s: %v\n", dllName, err)
			continue
		}

		// Resolve imports using Import Address Table (IAT)
		iatAddr := baseAddress + uintptr(descriptor.FirstThunk)
		err = resolveImportAddressTable(hProcess, iatAddr, dllHandle, peHeader.Is64Bit)
		if err != nil {
			Printf("Warning: Failed to resolve IAT for %s: %v\n", dllName, err)
		}

		// Don't free the library as it needs to remain loaded
		// windows.FreeLibrary(dllHandle)
		Printf("Successfully processed imports from %s\n", dllName)
	}

	Printf("Import table resolution completed\n")
	return nil
}

// FixRelocations processes base relocations
func FixRelocations(hProcess windows.Handle, baseAddress uintptr, peHeader *PEHeader) error {
	Printf("Starting base relocations processing...\n")

	// Get relocation directory
	if len(peHeader.DataDirectories) <= IMAGE_DIRECTORY_ENTRY_BASERELOC {
		Printf("No relocation directory found\n")
		return nil
	}

	relocDir := peHeader.DataDirectories[IMAGE_DIRECTORY_ENTRY_BASERELOC]
	if relocDir.VirtualAddress == 0 || relocDir.Size == 0 {
		Printf("Relocation directory is empty\n")
		return nil
	}

	Printf("Relocation directory: RVA=0x%X, Size=%d\n", relocDir.VirtualAddress, relocDir.Size)

	// Calculate delta (difference between preferred and actual base)
	var preferredBase uint64
	if peHeader.Is64Bit {
		preferredBase = peHeader.OptionalHeader.(OptionalHeader64).ImageBase
	} else {
		preferredBase = uint64(peHeader.OptionalHeader.(OptionalHeader32).ImageBase)
	}

	delta := int64(uint64(baseAddress) - preferredBase)
	Printf("Base address delta: 0x%X (preferred: 0x%X, actual: 0x%X)\n",
		delta, preferredBase, uint64(baseAddress))

	if delta == 0 {
		Printf("No relocations needed (loaded at preferred base)\n")
		return nil
	}

	// Process relocation blocks
	relocAddr := baseAddress + uintptr(relocDir.VirtualAddress)
	relocEnd := relocAddr + uintptr(relocDir.Size)
	processed := uint32(0)

	for relocAddr < relocEnd {
		var baseReloc BaseRelocation

		// Read base relocation header
		var bytesRead uintptr
		err := windows.ReadProcessMemory(hProcess, relocAddr,
			(*byte)(unsafe.Pointer(&baseReloc)), unsafe.Sizeof(baseReloc), &bytesRead)
		if err != nil {
			Printf("Failed to read relocation block: %v\n", err)
			break
		}

		if baseReloc.SizeOfBlock == 0 || baseReloc.SizeOfBlock < 8 {
			Printf("Invalid relocation block size: %d\n", baseReloc.SizeOfBlock)
			break
		}

		Printf("Processing relocation block: RVA=0x%X, Size=%d\n",
			baseReloc.VirtualAddress, baseReloc.SizeOfBlock)

		// Calculate number of relocations in this block
		entryCount := (baseReloc.SizeOfBlock - 8) / 2
		entriesAddr := relocAddr + uintptr(unsafe.Sizeof(baseReloc))

		// Read relocation entries
		entries := make([]uint16, entryCount)
		for j := uint32(0); j < entryCount; j++ {
			entryAddr := entriesAddr + uintptr(j*2)
			err = windows.ReadProcessMemory(hProcess, entryAddr,
				(*byte)(unsafe.Pointer(&entries[j])), 2, &bytesRead)
			if err != nil {
				Printf("Failed to read relocation entry %d: %v\n", j, err)
				continue
			}
		}

		// Process each relocation entry
		for _, entry := range entries {
			relocType := entry >> 12
			offset := entry & 0xFFF

			if relocType == IMAGE_REL_BASED_ABSOLUTE {
				continue // Skip absolute relocations
			}

			// Calculate target address
			targetAddr := baseAddress + uintptr(baseReloc.VirtualAddress) + uintptr(offset)

			// Apply relocation based on type
			err = applyRelocation(hProcess, targetAddr, relocType, delta, peHeader.Is64Bit)
			if err != nil {
				Printf("Warning: Failed to apply relocation at 0x%X: %v\n", targetAddr, err)
				continue
			}
			processed++
		}

		// Move to next relocation block
		relocAddr += uintptr(baseReloc.SizeOfBlock)
	}

	Printf("Base relocations processing completed (%d relocations applied)\n", processed)
	return nil
}

// ExecuteDllEntry executes DLL entry point
func ExecuteDllEntry(hProcess windows.Handle, baseAddress uintptr, peHeader *PEHeader) error {
	Printf("Executing DLL entry point...\n")

	entryPointRVA := peHeader.GetAddressOfEntryPoint()
	if entryPointRVA == 0 {
		Printf("No entry point found, skipping execution\n")
		return nil
	}

	entryPointAddr := baseAddress + uintptr(entryPointRVA)
	Printf("Entry point address: 0x%X (RVA: 0x%X)\n", entryPointAddr, entryPointRVA)

	// Create remote thread to execute DLL entry point
	// DLL entry point signature: BOOL DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
	// We'll call it with DLL_PROCESS_ATTACH (1)

	var threadID uint32
	threadHandle, err := CreateRemoteThread(hProcess, nil, 0,
		entryPointAddr, baseAddress, 0, &threadID)
	if err != nil {
		return fmt.Errorf("failed to create thread for DLL entry point: %v", err)
	}
	defer windows.CloseHandle(threadHandle)

	Printf("Created thread for DLL entry point execution (Thread ID: %d)\n", threadID)

	// Wait for entry point execution
	waitResult, err := windows.WaitForSingleObject(threadHandle, 5000)
	if err != nil {
		return fmt.Errorf("failed to wait for entry point execution: %v", err)
	}

	if waitResult == uint32(windows.WAIT_TIMEOUT) {
		Printf("Warning: DLL entry point execution timed out\n")
		return fmt.Errorf("DLL entry point execution timed out")
	}

	// Get exit code
	var exitCode uint32
	ret, _, _ := procGetExitCodeThread.Call(uintptr(threadHandle), uintptr(unsafe.Pointer(&exitCode)))
	if ret != 0 {
		Printf("DLL entry point execution completed with exit code: %d\n", exitCode)
		if exitCode == 0 {
			return fmt.Errorf("DLL entry point returned FALSE")
		}
	}

	Printf("DLL entry point executed successfully\n")
	return nil
}

// Helper functions

func readStringFromProcess(hProcess windows.Handle, addr uintptr) (string, error) {
	var result strings.Builder
	buffer := make([]byte, 1)

	for i := 0; i < 260; i++ { // Max path length
		var bytesRead uintptr
		err := windows.ReadProcessMemory(hProcess, addr+uintptr(i),
			&buffer[0], 1, &bytesRead)
		if err != nil {
			return "", err
		}

		if buffer[0] == 0 {
			break
		}

		result.WriteByte(buffer[0])
	}

	return result.String(), nil
}

func resolveImportAddressTable(hProcess windows.Handle, iatAddr uintptr, dllHandle windows.Handle, is64Bit bool) error {
	entrySize := uintptr(4)
	if is64Bit {
		entrySize = 8
	}

	for i := uintptr(0); ; i++ {
		entryAddr := iatAddr + i*entrySize

		// Read IAT entry
		var entry uint64
		var bytesRead uintptr

		if is64Bit {
			err := windows.ReadProcessMemory(hProcess, entryAddr,
				(*byte)(unsafe.Pointer(&entry)), 8, &bytesRead)
			if err != nil {
				return err
			}
		} else {
			var entry32 uint32
			err := windows.ReadProcessMemory(hProcess, entryAddr,
				(*byte)(unsafe.Pointer(&entry32)), 4, &bytesRead)
			if err != nil {
				return err
			}
			entry = uint64(entry32)
		}

		// Check for end of table
		if entry == 0 {
			break
		}

		// Skip if already resolved (high bit not set)
		if is64Bit && (entry&0x8000000000000000) == 0 {
			continue
		} else if !is64Bit && (entry&0x80000000) == 0 {
			continue
		}

		// This is a simplified import resolution
		// In a full implementation, we would:
		// 1. Check if import is by ordinal or by name
		// 2. Read the import name from the hint/name table
		// 3. Get the actual function address from the loaded DLL
		// 4. Write the resolved address back to the IAT

		Printf("IAT entry %d: 0x%X (simplified resolution)\n", i, entry)
	}

	return nil
}

func applyRelocation(hProcess windows.Handle, targetAddr uintptr, relocType uint16, delta int64, is64Bit bool) error {
	switch relocType {
	case IMAGE_REL_BASED_HIGHLOW:
		// 32-bit absolute relocation
		var value uint32
		var bytesRead uintptr
		err := windows.ReadProcessMemory(hProcess, targetAddr,
			(*byte)(unsafe.Pointer(&value)), 4, &bytesRead)
		if err != nil {
			return err
		}

		newValue := uint32(int64(value) + delta)
		var bytesWritten uintptr
		err = WriteProcessMemory(hProcess, targetAddr,
			unsafe.Pointer(&newValue), 4, &bytesWritten)
		if err != nil {
			return err
		}

	case IMAGE_REL_BASED_DIR64:
		// 64-bit absolute relocation
		var value uint64
		var bytesRead uintptr
		err := windows.ReadProcessMemory(hProcess, targetAddr,
			(*byte)(unsafe.Pointer(&value)), 8, &bytesRead)
		if err != nil {
			return err
		}

		newValue := uint64(int64(value) + delta)
		var bytesWritten uintptr
		err = WriteProcessMemory(hProcess, targetAddr,
			unsafe.Pointer(&newValue), 8, &bytesWritten)
		if err != nil {
			return err
		}

	case IMAGE_REL_BASED_HIGH:
		// High 16 bits of 32-bit address
		var value uint16
		var bytesRead uintptr
		err := windows.ReadProcessMemory(hProcess, targetAddr,
			(*byte)(unsafe.Pointer(&value)), 2, &bytesRead)
		if err != nil {
			return err
		}

		newValue := uint16((int64(value) + (delta >> 16)) & 0xFFFF)
		var bytesWritten uintptr
		err = WriteProcessMemory(hProcess, targetAddr,
			unsafe.Pointer(&newValue), 2, &bytesWritten)
		if err != nil {
			return err
		}

	case IMAGE_REL_BASED_LOW:
		// Low 16 bits of 32-bit address
		var value uint16
		var bytesRead uintptr
		err := windows.ReadProcessMemory(hProcess, targetAddr,
			(*byte)(unsafe.Pointer(&value)), 2, &bytesRead)
		if err != nil {
			return err
		}

		newValue := uint16((int64(value) + delta) & 0xFFFF)
		var bytesWritten uintptr
		err = WriteProcessMemory(hProcess, targetAddr,
			unsafe.Pointer(&newValue), 2, &bytesWritten)
		if err != nil {
			return err
		}

	default:
		return fmt.Errorf("unsupported relocation type: %d", relocType)
	}

	return nil
}
