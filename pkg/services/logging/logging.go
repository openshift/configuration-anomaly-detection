// Package logging wraps the zap logging package to provide easier access and initialization of the logger
package logging

import (
	"fmt"
	"log"
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// RawLogger is the raw global logger object used for calls wrapped by the logging package
var RawLogger = InitLogger("debug", "")

// InitLogger initializes a cluster-id specific child logger
func InitLogger(logLevelString string, clusterID string) *zap.SugaredLogger {
	logLevel, err := zap.ParseAtomicLevel(logLevelString)
	if err != nil {
		log.Fatalln("Invalid log level:", logLevelString)
	}

	pipelineName := os.Getenv("PIPELINE_NAME")
	if pipelineName == "" {
		fmt.Println("Warning: Unable to retrieve the pipeline ID on logger creation. Continuing with empty value.")
	}

	config := zap.NewProductionConfig()
	config.EncoderConfig.TimeKey = "timestamp"
	config.Level = logLevel
	config.EncoderConfig.EncodeTime = zapcore.RFC3339TimeEncoder
	config.EncoderConfig.StacktraceKey = "" // to hide stacktrace info

	logger, err := config.Build()
	if err != nil {
		log.Fatal(err)
	}

	logger = logger.With(zap.Field{Key: "cluster_id", Type: zapcore.StringType, String: clusterID},
		zap.Field{Key: "pipeline_name", Type: zapcore.StringType, String: pipelineName})

	return logger.Sugar()
}

// Info wraps zap's SugaredLogger.Info()
func Info(args ...interface{}) {
	RawLogger.Info(args...)
}

// Debug wraps zap's SugaredLogger.Debug()
func Debug(args ...interface{}) {
	RawLogger.Debug(args...)
}

// Warn wraps zap's SugaredLogger.Warn()
func Warn(args ...interface{}) {
	RawLogger.Warn(args...)
}

// Error wraps zap's SugaredLogger.Error()
func Error(args ...interface{}) {
	RawLogger.Error(args...)
}

// Fatal wraps zap's SugaredLogger.Fatal()
func Fatal(args ...interface{}) {
	RawLogger.Fatal(args...)
}

// Infof wraps zap's SugaredLogger.Infof()
func Infof(template string, args ...interface{}) {
	RawLogger.Infof(template, args...)
}

// Debugf wraps zap's SugaredLogger.Debugf()
func Debugf(template string, args ...interface{}) {
	RawLogger.Debugf(template, args...)
}

// Warnf wraps zap's SugaredLogger.Warnf()
func Warnf(template string, args ...interface{}) {
	RawLogger.Warnf(template, args...)
}

// Errorf wraps zap's SugaredLogger.Errorf()
func Errorf(template string, args ...interface{}) {
	RawLogger.Errorf(template, args...)
}

// Fatalf wraps zap's SugaredLogger.Fatalf()
func Fatalf(template string, args ...interface{}) {
	RawLogger.Fatalf(template, args...)
}
