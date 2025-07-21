package injector

import (
	"fmt"
	"log"
	"os"
	"sync"
)

// Logger interface defines methods for logging
type Logger interface {
	Info(msg string, fields ...interface{})
	Error(msg string, fields ...interface{})
	Warn(msg string, fields ...interface{})
	Debug(msg string, fields ...interface{})
}

// UnifiedLogger is a thread-safe logger implementation
type UnifiedLogger struct {
	mu          sync.RWMutex
	infoLogger  *log.Logger
	errorLogger *log.Logger
	warnLogger  *log.Logger
	debugLogger *log.Logger
	debugMode   bool
}

// NewUnifiedLogger creates a new unified logger
func NewUnifiedLogger(debugMode bool) *UnifiedLogger {
	flags := log.Ltime | log.Lmicroseconds
	return &UnifiedLogger{
		infoLogger:  log.New(os.Stdout, "[INFO] ", flags),
		errorLogger: log.New(os.Stderr, "[ERROR] ", flags),
		warnLogger:  log.New(os.Stdout, "[WARN] ", flags),
		debugLogger: log.New(os.Stdout, "[DEBUG] ", flags),
		debugMode:   debugMode,
	}
}

// formatFields formats the fields for logging
func formatFields(fields []interface{}) string {
	if len(fields) == 0 {
		return ""
	}

	result := " |"
	for i := 0; i < len(fields)-1; i += 2 {
		if i < len(fields)-1 {
			result += fmt.Sprintf(" %v=%v", fields[i], fields[i+1])
		}
	}
	return result
}

func (l *UnifiedLogger) Info(msg string, fields ...interface{}) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	l.infoLogger.Printf("%s%s", msg, formatFields(fields))
}

func (l *UnifiedLogger) Error(msg string, fields ...interface{}) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	l.errorLogger.Printf("%s%s", msg, formatFields(fields))
}

func (l *UnifiedLogger) Warn(msg string, fields ...interface{}) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	l.warnLogger.Printf("%s%s", msg, formatFields(fields))
}

func (l *UnifiedLogger) Debug(msg string, fields ...interface{}) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.debugMode {
		l.debugLogger.Printf("%s%s", msg, formatFields(fields))
	}
}

// SetDebugMode enables or disables debug logging
func (l *UnifiedLogger) SetDebugMode(enabled bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.debugMode = enabled
}

// Global logger instance for the injector package
var globalLogger Logger = &SilentLogger{} // Default to silent

// SilentLogger discards all output (for when no logger is set)
type SilentLogger struct{}

func (l *SilentLogger) Info(msg string, fields ...interface{}) {
	// Do nothing - silent
}

func (l *SilentLogger) Warn(msg string, fields ...interface{}) {
	// Do nothing - silent
}

func (l *SilentLogger) Error(msg string, fields ...interface{}) {
	// Do nothing - silent
}

func (l *SilentLogger) Debug(msg string, fields ...interface{}) {
	// Do nothing - silent
}

// SetLogger sets the global logger
func SetLogger(logger Logger) {
	globalLogger = logger
}

// GetLogger returns the current global logger
func GetLogger() Logger {
	return globalLogger
}

// InitLogger initializes the package logger (alias for SetLogger)
func InitLogger(logger Logger) {
	if logger == nil {
		globalLogger = NewUnifiedLogger(false)
	} else {
		globalLogger = logger
	}
}

// getLogger returns the package logger or creates a default one
func getLogger() Logger {
	if globalLogger == nil {
		globalLogger = NewUnifiedLogger(false)
	}
	return globalLogger
}

// Convenience functions that use the global logger
func Info(msg string, fields ...interface{}) {
	globalLogger.Info(msg, fields...)
}

func Warn(msg string, fields ...interface{}) {
	globalLogger.Warn(msg, fields...)
}

func Error(msg string, fields ...interface{}) {
	globalLogger.Error(msg, fields...)
}

func Debug(msg string, fields ...interface{}) {
	globalLogger.Debug(msg, fields...)
}

// Compatibility functions for migration
// These will be removed once all Printf/Println calls are replaced

// Printf logs at info level (deprecated - use logger.Info)
func Printf(format string, v ...interface{}) {
	globalLogger.Info(fmt.Sprintf(format, v...))
}

// Println logs at info level (deprecated - use logger.Info)
func Println(v ...interface{}) {
	globalLogger.Info(fmt.Sprint(v...))
}
