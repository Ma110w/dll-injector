package injector

import (
	"fmt"
)

// Logger interface defines the logging methods
type Logger interface {
	Info(msg string, fields ...interface{})
	Warn(msg string, fields ...interface{})
	Error(msg string, fields ...interface{})
	Debug(msg string, fields ...interface{})
}

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

// Global logger instance
var globalLogger Logger = &SilentLogger{} // Default to silent

// SetLogger sets the global logger
func SetLogger(logger Logger) {
	globalLogger = logger
}

// GetLogger returns the current global logger
func GetLogger() Logger {
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

// Printf provides backward compatibility for printf-style logging
func Printf(format string, args ...interface{}) {
	globalLogger.Info(fmt.Sprintf(format, args...))
}

// Println provides backward compatibility for println-style logging
func Println(args ...interface{}) {
	globalLogger.Info(fmt.Sprint(args...))
}
