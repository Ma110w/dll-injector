package injector

import (
	"fmt"
	"runtime"
	"strings"
)

// ErrorType represents the type of error
type ErrorType int

const (
	// Error types
	ErrorTypeUnknown ErrorType = iota
	ErrorTypeInvalidInput
	ErrorTypePermission
	ErrorTypeMemoryAllocation
	ErrorTypeProcessAccess
	ErrorTypeArchitectureMismatch
	ErrorTypePEParsing
	ErrorTypeInjectionFailed
	ErrorTypeTimeout
	ErrorTypeSystemCall
	ErrorTypeResourceExhausted
	ErrorTypeNotSupported
)

// ErrorSeverity represents the severity of an error
type ErrorSeverity int

const (
	// Error severities
	SeverityInfo ErrorSeverity = iota
	SeverityWarning
	SeverityError
	SeverityCritical
)

// InjectorError represents a structured error with context
type InjectorError struct {
	Type        ErrorType
	Severity    ErrorSeverity
	Message     string
	Cause       error
	Context     map[string]interface{}
	Recoverable bool
	Suggestions []string
	StackTrace  string
}

// Error implements the error interface
func (e *InjectorError) Error() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[%s] %s: %s", e.severityString(), e.typeString(), e.Message))

	if e.Cause != nil {
		sb.WriteString(fmt.Sprintf(" (caused by: %v)", e.Cause))
	}

	if len(e.Suggestions) > 0 {
		sb.WriteString("\nSuggestions:")
		for i, suggestion := range e.Suggestions {
			sb.WriteString(fmt.Sprintf("\n  %d. %s", i+1, suggestion))
		}
	}

	return sb.String()
}

// Unwrap returns the underlying error
func (e *InjectorError) Unwrap() error {
	return e.Cause
}

// IsRecoverable returns whether the error is recoverable
func (e *InjectorError) IsRecoverable() bool {
	return e.Recoverable
}

// AddContext adds context information to the error
func (e *InjectorError) AddContext(key string, value interface{}) *InjectorError {
	if e.Context == nil {
		e.Context = make(map[string]interface{})
	}
	e.Context[key] = value
	return e
}

// AddSuggestion adds a suggestion for resolving the error
func (e *InjectorError) AddSuggestion(suggestion string) *InjectorError {
	e.Suggestions = append(e.Suggestions, suggestion)
	return e
}

// typeString returns a string representation of the error type
func (e *InjectorError) typeString() string {
	switch e.Type {
	case ErrorTypeInvalidInput:
		return "InvalidInput"
	case ErrorTypePermission:
		return "Permission"
	case ErrorTypeMemoryAllocation:
		return "MemoryAllocation"
	case ErrorTypeProcessAccess:
		return "ProcessAccess"
	case ErrorTypeArchitectureMismatch:
		return "ArchitectureMismatch"
	case ErrorTypePEParsing:
		return "PEParsing"
	case ErrorTypeInjectionFailed:
		return "InjectionFailed"
	case ErrorTypeTimeout:
		return "Timeout"
	case ErrorTypeSystemCall:
		return "SystemCall"
	case ErrorTypeResourceExhausted:
		return "ResourceExhausted"
	case ErrorTypeNotSupported:
		return "NotSupported"
	default:
		return "Unknown"
	}
}

// severityString returns a string representation of the error severity
func (e *InjectorError) severityString() string {
	switch e.Severity {
	case SeverityInfo:
		return "INFO"
	case SeverityWarning:
		return "WARN"
	case SeverityError:
		return "ERROR"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// NewError creates a new InjectorError
func NewError(errType ErrorType, message string, cause error) *InjectorError {
	// Capture stack trace
	buf := make([]byte, 4096)
	n := runtime.Stack(buf, false)

	return &InjectorError{
		Type:        errType,
		Severity:    SeverityError,
		Message:     message,
		Cause:       cause,
		Context:     make(map[string]interface{}),
		Recoverable: false,
		StackTrace:  string(buf[:n]),
	}
}

// NewRecoverableError creates a new recoverable error
func NewRecoverableError(errType ErrorType, message string, cause error) *InjectorError {
	err := NewError(errType, message, cause)
	err.Recoverable = true
	err.Severity = SeverityWarning
	return err
}

// NewCriticalError creates a new critical error
func NewCriticalError(errType ErrorType, message string, cause error) *InjectorError {
	err := NewError(errType, message, cause)
	err.Severity = SeverityCritical
	err.Recoverable = false
	return err
}

// Common error constructors

// ErrInvalidInput creates an invalid input error
func ErrInvalidInput(message string, input interface{}) *InjectorError {
	return NewError(ErrorTypeInvalidInput, message, nil).
		AddContext("input", input).
		AddSuggestion("Verify the input parameters are correct")
}

// ErrPermissionDenied creates a permission denied error
func ErrPermissionDenied(operation string) *InjectorError {
	return NewError(ErrorTypePermission,
		fmt.Sprintf("Permission denied for operation: %s", operation), nil).
		AddContext("operation", operation).
		AddSuggestion("Run the application as Administrator").
		AddSuggestion("Check if the target process is protected")
}

// ErrMemoryAllocation creates a memory allocation error
func ErrMemoryAllocation(size uintptr, err error) *InjectorError {
	return NewError(ErrorTypeMemoryAllocation,
		fmt.Sprintf("Failed to allocate %d bytes of memory", size), err).
		AddContext("size", size).
		AddSuggestion("Close other applications to free memory").
		AddSuggestion("Try a smaller DLL or different injection method")
}

// ErrProcessAccess creates a process access error
func ErrProcessAccess(pid uint32, err error) *InjectorError {
	return NewError(ErrorTypeProcessAccess,
		fmt.Sprintf("Cannot access process %d", pid), err).
		AddContext("pid", pid).
		AddSuggestion("Verify the process ID is correct").
		AddSuggestion("Check if the process is still running").
		AddSuggestion("Run with elevated privileges")
}

// ErrArchitectureMismatch creates an architecture mismatch error
func ErrArchitectureMismatch(processArch, dllArch string) *InjectorError {
	return NewError(ErrorTypeArchitectureMismatch,
		fmt.Sprintf("Architecture mismatch: process is %s but DLL is %s", processArch, dllArch), nil).
		AddContext("process_arch", processArch).
		AddContext("dll_arch", dllArch).
		AddSuggestion(fmt.Sprintf("Use a %s version of the DLL", processArch)).
		AddSuggestion("Recompile the DLL for the target architecture")
}

// ErrPEParsing creates a PE parsing error
func ErrPEParsing(reason string, err error) *InjectorError {
	return NewError(ErrorTypePEParsing,
		fmt.Sprintf("Failed to parse PE file: %s", reason), err).
		AddSuggestion("Verify the file is a valid Windows PE file").
		AddSuggestion("Check if the file is corrupted")
}

// ErrInjectionFailed creates an injection failure error
func ErrInjectionFailed(method string, reason string, err error) *InjectorError {
	return NewError(ErrorTypeInjectionFailed,
		fmt.Sprintf("Injection failed using %s: %s", method, reason), err).
		AddContext("method", method).
		AddSuggestion("Try a different injection method").
		AddSuggestion("Check if anti-virus is blocking the injection")
}

// ErrTimeout creates a timeout error
func ErrTimeout(operation string, timeout int) *InjectorError {
	return NewRecoverableError(ErrorTypeTimeout,
		fmt.Sprintf("Operation '%s' timed out after %d seconds", operation, timeout), nil).
		AddContext("operation", operation).
		AddContext("timeout", timeout).
		AddSuggestion("Increase the timeout duration").
		AddSuggestion("Check if the target process is responding")
}

// IsRecoverableError checks if an error is recoverable
func IsRecoverableError(err error) bool {
	if injErr, ok := err.(*InjectorError); ok {
		return injErr.IsRecoverable()
	}
	return false
}

// GetErrorType returns the type of an error
func GetErrorType(err error) ErrorType {
	if injErr, ok := err.(*InjectorError); ok {
		return injErr.Type
	}
	return ErrorTypeUnknown
}

// WrapError wraps an existing error with additional context
func WrapError(err error, errType ErrorType, message string) *InjectorError {
	if err == nil {
		return nil
	}

	// If it's already an InjectorError, preserve its context
	if injErr, ok := err.(*InjectorError); ok {
		newErr := &InjectorError{
			Type:        errType,
			Severity:    injErr.Severity,
			Message:     message,
			Cause:       injErr,
			Context:     injErr.Context,
			Recoverable: injErr.Recoverable,
			Suggestions: injErr.Suggestions,
			StackTrace:  injErr.StackTrace,
		}
		return newErr
	}

	return NewError(errType, message, err)
}
