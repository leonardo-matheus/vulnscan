package log

import (
	"io"
	"log"
	"os"
)

var (
	debugLogger  *log.Logger
	infoLogger   *log.Logger
	warnLogger   *log.Logger
	errorLogger  *log.Logger
	isDebug      bool
)

func init() {
	debugLogger = log.New(os.Stderr, "[DEBUG] ", 0)
	infoLogger = log.New(os.Stderr, "", 0)
	warnLogger = log.New(os.Stderr, "[WARN] ", 0)
	errorLogger = log.New(os.Stderr, "[ERROR] ", log.Lshortfile)
}

func SetDebug(enabled bool) {
	isDebug = enabled
}

func SetOutput(w io.Writer) {
	debugLogger.SetOutput(w)
	infoLogger.SetOutput(w)
	warnLogger.SetOutput(w)
	errorLogger.SetOutput(w)
}

func Debug(format string, args ...interface{}) {
	if isDebug {
		debugLogger.Printf(format, args...)
	}
}

func Info(format string, args ...interface{}) {
	infoLogger.Printf(format, args...)
}

func Warn(format string, args ...interface{}) {
	warnLogger.Printf(format, args...)
}

func Error(format string, args ...interface{}) {
	errorLogger.Printf(format, args...)
}

func Fatal(format string, args ...interface{}) {
	errorLogger.Fatalf(format, args...)
}
