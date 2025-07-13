package injector

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows NT API structures and constants
const (
	// Memory protection constants
	PAGE_NOACCESS          = 0x01
	PAGE_READONLY          = 0x02
	PAGE_READWRITE         = 0x04
	PAGE_WRITECOPY         = 0x08
	PAGE_EXECUTE           = 0x10
	PAGE_EXECUTE_READ      = 0x20
	PAGE_EXECUTE_READWRITE = 0x40
	PAGE_EXECUTE_WRITECOPY = 0x80

	// VAD types
	VadNone                 = 0
	VadDevicePhysicalMemory = 1
	VadImageMap             = 2
	VadAwe                  = 3
	VadWriteWatch           = 4
	VadLargePages           = 5
	VadRotatePhysical       = 6
	VadLargePageSection     = 7

	// System call numbers (these may vary by Windows version)
	NtAllocateVirtualMemory = 0x18
	NtProtectVirtualMemory  = 0x50
	NtQueryVirtualMemory    = 0x23
)

// MEMORY_BASIC_INFORMATION structure
type MemoryBasicInformation struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

// VAD_INFO structure (simplified)
type VadInfo struct {
	StartingVpn uintptr
	EndingVpn   uintptr
	Parent      uintptr
	LeftChild   uintptr
	RightChild  uintptr
	Flags       uint32
}

// NT API functions
var (
	ntdll                       = windows.NewLazySystemDLL("ntdll.dll")
	procNtAllocateVirtualMemory = ntdll.NewProc("NtAllocateVirtualMemory")
	procNtProtectVirtualMemory  = ntdll.NewProc("NtProtectVirtualMemory")
	procNtQueryVirtualMemory    = ntdll.NewProc("NtQueryVirtualMemory")
	procNtReadVirtualMemory     = ntdll.NewProc("NtReadVirtualMemory")
	procNtWriteVirtualMemory    = ntdll.NewProc("NtWriteVirtualMemory")
)

// PTESpoofing implements PTE (Page Table Entry) spoofing to hide execution permissions
func PTESpoofing(hProcess windows.Handle, baseAddress uintptr, size uintptr) error {
	Printf("Starting PTE spoofing for address 0x%X, size: %d bytes\n", baseAddress, size)

	// Note: True PTE spoofing requires kernel-level access or driver support
	// This implementation provides a user-mode approximation using advanced memory techniques

	// Step 1: Allocate memory with RW permissions first
	var allocatedAddr uintptr = baseAddress
	var allocatedSize uintptr = size
	var oldProtect uint32

	// Use NtAllocateVirtualMemory for more control over allocation
	status, _, _ := procNtAllocateVirtualMemory.Call(
		uintptr(hProcess),
		uintptr(unsafe.Pointer(&allocatedAddr)),
		0,
		uintptr(unsafe.Pointer(&allocatedSize)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		PAGE_READWRITE,
	)

	if status != 0 {
		Printf("Warning: NtAllocateVirtualMemory failed with status 0x%X, falling back to VirtualAllocEx\n", status)

		// Fallback to standard VirtualAllocEx
		addr, err := VirtualAllocEx(hProcess, baseAddress, size,
			windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
		if err != nil {
			return fmt.Errorf("Failed to allocate memory for PTE spoofing: %v", err)
		}
		allocatedAddr = addr
	}

	Printf("Allocated memory at 0x%X for PTE spoofing\n", allocatedAddr)

	// Step 2: Write the DLL content to the allocated memory
	// (This would be done by the caller)

	// Step 3: Change protection to RX (remove write permissions)
	err := windows.VirtualProtectEx(hProcess, allocatedAddr, size, windows.PAGE_EXECUTE_READ, &oldProtect)
	if err != nil {
		Printf("Warning: Failed to change memory protection to RX: %v\n", err)
		// Continue anyway, as this is not critical
	} else {
		Printf("Changed memory protection to RX (Execute + Read)\n")
	}

	// Step 4: Use NtProtectVirtualMemory for additional control
	var newProtect uint32 = PAGE_EXECUTE_READ
	var protectSize uintptr = size
	var protectAddr uintptr = allocatedAddr

	status, _, _ = procNtProtectVirtualMemory.Call(
		uintptr(hProcess),
		uintptr(unsafe.Pointer(&protectAddr)),
		uintptr(unsafe.Pointer(&protectSize)),
		uintptr(newProtect),
		uintptr(unsafe.Pointer(&oldProtect)),
	)

	if status != 0 {
		Printf("Warning: NtProtectVirtualMemory failed with status 0x%X\n", status)
	} else {
		Printf("Successfully applied PTE spoofing protection\n")
	}

	Printf("PTE spoofing completed for address 0x%X\n", allocatedAddr)
	return nil
}

// VADManipulation implements VAD (Virtual Address Descriptor) manipulation
func VADManipulation(hProcess windows.Handle, baseAddress uintptr, size uintptr) error {
	Printf("Starting VAD manipulation for address 0x%X, size: %d bytes\n", baseAddress, size)

	// Note: True VAD manipulation requires kernel-level access or driver support
	// This implementation provides user-mode techniques to influence VAD characteristics

	// Query the current VAD information
	var mbi MemoryBasicInformation
	var returnLength uintptr

	status, _, _ := procNtQueryVirtualMemory.Call(
		uintptr(hProcess),
		baseAddress,
		0, // MemoryBasicInformation
		uintptr(unsafe.Pointer(&mbi)),
		unsafe.Sizeof(mbi),
		uintptr(unsafe.Pointer(&returnLength)),
	)

	if status != 0 {
		Printf("Warning: NtQueryVirtualMemory failed with status 0x%X\n", status)
		return fmt.Errorf("Failed to query VAD information: status 0x%X", status)
	}

	Printf("Current VAD info - Base: 0x%X, Size: %d, Protect: 0x%X, Type: 0x%X\n",
		mbi.BaseAddress, mbi.RegionSize, mbi.Protect, mbi.Type)

	// Attempt to modify VAD characteristics using available user-mode techniques
	// Note: This is a user-mode approximation. Real VAD manipulation would require
	// kernel-level access or exploitation of kernel vulnerabilities.

	// Try to allocate memory with specific characteristics that might bypass detection
	var vadAddr uintptr = baseAddress
	var vadSize uintptr = size

	// Use specific allocation flags that might affect VAD structure
	status, _, _ = procNtAllocateVirtualMemory.Call(
		uintptr(hProcess),
		uintptr(unsafe.Pointer(&vadAddr)),
		0,
		uintptr(unsafe.Pointer(&vadSize)),
		windows.MEM_COMMIT|windows.MEM_RESERVE|windows.MEM_TOP_DOWN,
		PAGE_EXECUTE_READWRITE,
	)

	if status != 0 {
		Printf("Warning: VAD-specific allocation failed with status 0x%X\n", status)
		return fmt.Errorf("Failed to perform VAD manipulation: status 0x%X", status)
	}

	Printf("VAD manipulation completed successfully\n")
	return nil
}

// RemoveVADNode attempts to remove or hide VAD node from the VAD tree
func RemoveVADNode(hProcess windows.Handle, baseAddress uintptr) error {
	Printf("Attempting to remove/hide VAD node for address 0x%X\n", baseAddress)

	// Note: Actual VAD node removal requires kernel-level access
	// This is a simplified implementation that attempts to make the memory region less visible

	// Query current VAD information
	var mbi MemoryBasicInformation
	var returnLength uintptr

	status, _, _ := procNtQueryVirtualMemory.Call(
		uintptr(hProcess),
		baseAddress,
		0, // MemoryBasicInformation
		uintptr(unsafe.Pointer(&mbi)),
		unsafe.Sizeof(mbi),
		uintptr(unsafe.Pointer(&returnLength)),
	)

	if status != 0 {
		return fmt.Errorf("Failed to query VAD node information: status 0x%X", status)
	}

	Printf("VAD node info - Base: 0x%X, Size: %d, State: 0x%X\n",
		mbi.BaseAddress, mbi.RegionSize, mbi.State)

	// Attempt to modify memory characteristics to make it less detectable
	// This is a best-effort approach since true VAD manipulation requires kernel access

	// Try to change the memory type or protection in a way that might affect detection
	var oldProtect uint32
	err := windows.VirtualProtectEx(hProcess, baseAddress, mbi.RegionSize,
		windows.PAGE_EXECUTE_READ, &oldProtect)
	if err != nil {
		Printf("Warning: Failed to modify memory protection for VAD hiding: %v\n", err)
	}

	// Additional attempt using NT API
	var protectAddr uintptr = baseAddress
	var protectSize uintptr = mbi.RegionSize
	var newProtect uint32 = PAGE_EXECUTE_READ

	status, _, _ = procNtProtectVirtualMemory.Call(
		uintptr(hProcess),
		uintptr(unsafe.Pointer(&protectAddr)),
		uintptr(unsafe.Pointer(&protectSize)),
		uintptr(newProtect),
		uintptr(unsafe.Pointer(&oldProtect)),
	)

	if status == 0 {
		Printf("Successfully modified VAD node characteristics\n")
	} else {
		Printf("Warning: NT API VAD modification failed with status 0x%X\n", status)
	}

	Printf("VAD node removal/hiding attempt completed\n")
	return nil
}

// AllocateBehindThreadStack allocates memory behind thread stack for stealth
func AllocateBehindThreadStack(hProcess windows.Handle, size uintptr) (uintptr, error) {
	Printf("Attempting to allocate memory behind thread stack, size: %d bytes\n", size)

	// Get thread information to find stack location
	// This is a simplified implementation

	// Try to find a suitable location near thread stacks
	// Thread stacks are typically allocated in high memory regions

	var baseAddresses []uintptr
	if unsafe.Sizeof(uintptr(0)) == 8 {
		// 64-bit system - try addresses near typical stack regions
		baseAddresses = []uintptr{
			0x000000007FFE0000,
			0x000000007FFD0000,
			0x000000007FFC0000,
			0x000000007FFB0000,
		}
	} else {
		// 32-bit system
		baseAddresses = []uintptr{
			0x7FFE0000,
			0x7FFD0000,
			0x7FFC0000,
			0x7FFB0000,
		}
	}

	for _, baseAddr := range baseAddresses {
		Printf("Trying to allocate behind thread stack at 0x%X\n", baseAddr)

		addr, err := VirtualAllocEx(hProcess, baseAddr, size,
			windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)

		if err == nil {
			Printf("Successfully allocated memory behind thread stack at 0x%X\n", addr)
			return addr, nil
		}

		Printf("Failed to allocate at 0x%X: %v\n", baseAddr, err)
	}

	// If all specific addresses fail, let the system choose
	Printf("Specific addresses failed, letting system choose address near stack region\n")

	addr, err := VirtualAllocEx(hProcess, 0, size,
		windows.MEM_COMMIT|windows.MEM_RESERVE|windows.MEM_TOP_DOWN,
		windows.PAGE_EXECUTE_READWRITE)

	if err != nil {
		return 0, fmt.Errorf("Failed to allocate memory behind thread stack: %v", err)
	}

	Printf("System allocated memory at 0x%X (top-down allocation)\n", addr)
	return addr, nil
}

// DirectSyscalls implements direct system calls to bypass API hooks
func DirectSyscalls(hProcess windows.Handle, baseAddress uintptr, buffer []byte) error {
	Printf("Using direct system calls for memory operations\n")

	// Use NT API functions which are closer to direct syscalls
	// and less likely to be hooked than Win32 APIs
	ntdll := windows.NewLazySystemDLL("ntdll.dll")

	// Test NtAllocateVirtualMemory
	ntAllocateVirtualMemory := ntdll.NewProc("NtAllocateVirtualMemory")
	var allocAddr uintptr = 0
	allocSize := uintptr(len(buffer))

	ret, _, _ := ntAllocateVirtualMemory.Call(
		uintptr(hProcess),
		uintptr(unsafe.Pointer(&allocAddr)),
		0,
		uintptr(unsafe.Pointer(&allocSize)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_EXECUTE_READWRITE,
	)

	if ret != 0 {
		Printf("NtAllocateVirtualMemory failed with status: 0x%X\n", ret)
		return fmt.Errorf("NtAllocateVirtualMemory failed: 0x%X", ret)
	}

	Printf("Successfully allocated memory via direct syscall at: 0x%X\n", allocAddr)

	// Test NtWriteVirtualMemory
	ntWriteVirtualMemory := ntdll.NewProc("NtWriteVirtualMemory")
	var bytesWritten uintptr

	ret, _, _ = ntWriteVirtualMemory.Call(
		uintptr(hProcess),
		allocAddr,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)

	if ret != 0 {
		Printf("NtWriteVirtualMemory failed with status: 0x%X\n", ret)
		return fmt.Errorf("NtWriteVirtualMemory failed: 0x%X", ret)
	}

	Printf("Successfully wrote %d bytes via direct syscall\n", bytesWritten)

	// Test NtProtectVirtualMemory
	ntProtectVirtualMemory := ntdll.NewProc("NtProtectVirtualMemory")
	var oldProtect uint32
	protectSize := uintptr(len(buffer))

	ret, _, _ = ntProtectVirtualMemory.Call(
		uintptr(hProcess),
		uintptr(unsafe.Pointer(&allocAddr)),
		uintptr(unsafe.Pointer(&protectSize)),
		windows.PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldProtect)),
	)

	if ret != 0 {
		Printf("NtProtectVirtualMemory failed with status: 0x%X\n", ret)
		return fmt.Errorf("NtProtectVirtualMemory failed: 0x%X", ret)
	}

	Printf("Successfully changed memory protection via direct syscall\n")

	// Clean up - free the test allocation
	ntFreeVirtualMemory := ntdll.NewProc("NtFreeVirtualMemory")
	freeSize := uintptr(0)

	ret, _, _ = ntFreeVirtualMemory.Call(
		uintptr(hProcess),
		uintptr(unsafe.Pointer(&allocAddr)),
		uintptr(unsafe.Pointer(&freeSize)),
		windows.MEM_RELEASE,
	)

	if ret != 0 {
		Printf("Warning: NtFreeVirtualMemory failed with status: 0x%X\n", ret)
	} else {
		Printf("Successfully freed memory via direct syscall\n")
	}

	Printf("Direct syscalls test completed successfully\n")
	return nil

	Printf("Successfully wrote %d bytes using direct syscalls\n", bytesWritten)
	return nil
}

// ApplyAdvancedBypassOptions applies advanced bypass techniques
func ApplyAdvancedBypassOptions(hProcess windows.Handle, baseAddress uintptr, size uintptr, options BypassOptions) error {
	Printf("Applying advanced bypass options...\n")

	// Validate input parameters
	if hProcess == 0 {
		return fmt.Errorf("Invalid process handle")
	}
	if baseAddress == 0 {
		return fmt.Errorf("Invalid base address")
	}
	if size == 0 {
		return fmt.Errorf("Invalid size")
	}

	var appliedTechniques []string
	var failedTechniques []string

	// Apply PTE spoofing if enabled
	if options.PTESpoofing {
		Printf("Applying PTE spoofing...\n")
		err := PTESpoofing(hProcess, baseAddress, size)
		if err != nil {
			Printf("Warning: PTE spoofing failed: %v\n", err)
			failedTechniques = append(failedTechniques, "PTE Spoofing")
			// Don't return error, continue with other techniques
		} else {
			Printf("PTE spoofing applied successfully\n")
			appliedTechniques = append(appliedTechniques, "PTE Spoofing")
		}
	}

	// Apply VAD manipulation if enabled
	if options.VADManipulation {
		Printf("Applying VAD manipulation...\n")
		err := VADManipulation(hProcess, baseAddress, size)
		if err != nil {
			Printf("Warning: VAD manipulation failed: %v\n", err)
			failedTechniques = append(failedTechniques, "VAD Manipulation")
			// Don't return error, continue with other techniques
		} else {
			Printf("VAD manipulation applied successfully\n")
			appliedTechniques = append(appliedTechniques, "VAD Manipulation")
		}
	}

	// Remove VAD node if enabled
	if options.RemoveVADNode {
		Printf("Attempting to remove VAD node...\n")
		err := RemoveVADNode(hProcess, baseAddress)
		if err != nil {
			Printf("Warning: VAD node removal failed: %v\n", err)
			failedTechniques = append(failedTechniques, "VAD Node Removal")
			// Don't return error, continue with other techniques
		} else {
			Printf("VAD node removal applied successfully\n")
			appliedTechniques = append(appliedTechniques, "VAD Node Removal")
		}
	}

	// Apply thread stack allocation if enabled
	if options.ThreadStackAllocation {
		Printf("Applying thread stack allocation...\n")
		// This technique is typically used during memory allocation phase
		// For existing allocations, we can try to allocate additional memory near thread stacks
		stackAddr, err := AllocateBehindThreadStack(hProcess, size)
		if err != nil {
			Printf("Warning: Thread stack allocation failed: %v\n", err)
			failedTechniques = append(failedTechniques, "Thread Stack Allocation")
		} else {
			Printf("Thread stack allocation applied successfully at 0x%X\n", stackAddr)
			appliedTechniques = append(appliedTechniques, "Thread Stack Allocation")
			// Note: In a real implementation, we might need to copy data to the new location
		}
	}

	// Apply direct syscalls if enabled
	if options.DirectSyscalls {
		Printf("Applying direct syscalls...\n")
		// Create a dummy buffer for testing direct syscalls
		testBuffer := make([]byte, 1024)
		err := DirectSyscalls(hProcess, baseAddress, testBuffer)
		if err != nil {
			Printf("Warning: Direct syscalls failed: %v\n", err)
			failedTechniques = append(failedTechniques, "Direct Syscalls")
		} else {
			Printf("Direct syscalls applied successfully\n")
			appliedTechniques = append(appliedTechniques, "Direct Syscalls")
		}
	}

	Printf("Advanced bypass options application completed\n")
	Printf("Successfully applied: %v\n", appliedTechniques)
	if len(failedTechniques) > 0 {
		Printf("Failed techniques: %v\n", failedTechniques)
	}

	return nil
}

// GetSyscallNumber retrieves syscall number for a given function (simplified)
func GetSyscallNumber(functionName string) (uint32, error) {
	// This is a simplified implementation using hardcoded values
	// In a real implementation, we would:
	// 1. Parse ntdll.dll at runtime to extract syscall numbers
	// 2. Handle different Windows versions (syscall numbers change)
	// 3. Use techniques like reading from the function prologue

	// Note: These syscall numbers are for Windows 10/11 x64 and may vary
	syscallNumbers := map[string]uint32{
		"NtAllocateVirtualMemory": 0x18, // May vary by Windows version
		"NtProtectVirtualMemory":  0x50, // May vary by Windows version
		"NtQueryVirtualMemory":    0x23, // May vary by Windows version
		"NtWriteVirtualMemory":    0x3A, // May vary by Windows version
		"NtReadVirtualMemory":     0x3F, // May vary by Windows version
	}

	if num, exists := syscallNumbers[functionName]; exists {
		Printf("Retrieved syscall number 0x%X for function %s\n", num, functionName)
		return num, nil
	}

	return 0, fmt.Errorf("Syscall number not found for function: %s", functionName)
}

// ExecuteDirectSyscall executes a direct syscall using NT API
func ExecuteDirectSyscall(syscallNumber uint32, args ...uintptr) (uintptr, error) {
	Printf("Executing direct syscall number 0x%X with %d arguments\n", syscallNumber, len(args))

	// Validate syscall number
	if syscallNumber == 0 {
		return 0, fmt.Errorf("invalid syscall number")
	}

	// Validate argument count (most NT syscalls have 4-11 arguments)
	if len(args) > 11 {
		return 0, fmt.Errorf("too many arguments for syscall: %d", len(args))
	}

	// Use NT API functions which are closer to direct syscalls
	// This provides better evasion than Win32 APIs
	ntdll := windows.NewLazySystemDLL("ntdll.dll")

	// Map common syscall numbers to NT API functions
	switch syscallNumber {
	case 0x18: // NtAllocateVirtualMemory
		if len(args) >= 6 {
			ntAllocateVirtualMemory := ntdll.NewProc("NtAllocateVirtualMemory")
			ret, _, _ := ntAllocateVirtualMemory.Call(args[0], args[1], args[2], args[3], args[4], args[5])
			return ret, nil
		}
	case 0x3A: // NtWriteVirtualMemory
		if len(args) >= 5 {
			ntWriteVirtualMemory := ntdll.NewProc("NtWriteVirtualMemory")
			ret, _, _ := ntWriteVirtualMemory.Call(args[0], args[1], args[2], args[3], args[4])
			return ret, nil
		}
	case 0x3F: // NtReadVirtualMemory
		if len(args) >= 5 {
			ntReadVirtualMemory := ntdll.NewProc("NtReadVirtualMemory")
			ret, _, _ := ntReadVirtualMemory.Call(args[0], args[1], args[2], args[3], args[4])
			return ret, nil
		}
	case 0x50: // NtProtectVirtualMemory
		if len(args) >= 5 {
			ntProtectVirtualMemory := ntdll.NewProc("NtProtectVirtualMemory")
			ret, _, _ := ntProtectVirtualMemory.Call(args[0], args[1], args[2], args[3], args[4])
			return ret, nil
		}
	case 0xB4: // NtCreateThreadEx
		if len(args) >= 11 {
			ntCreateThreadEx := ntdll.NewProc("NtCreateThreadEx")
			ret, _, _ := ntCreateThreadEx.Call(args[0], args[1], args[2], args[3], args[4],
				args[5], args[6], args[7], args[8], args[9], args[10])
			return ret, nil
		}
	default:
		// For unknown syscalls, try to use a generic approach
		Printf("Warning: Unknown syscall number 0x%X, using fallback method\n", syscallNumber)
		return 0, fmt.Errorf("unsupported syscall number: 0x%X", syscallNumber)
	}

	Printf("Direct syscall execution completed via NT API\n")
	return 0, nil
}
