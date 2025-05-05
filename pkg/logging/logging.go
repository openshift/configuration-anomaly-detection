// Package logging wraps the zap logging package to provide easier access and initialization of the logger
package logging

import (
	"log"
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var LogLevelString = getLogLevel()

// RawLogger is the raw global logger object used for calls wrapped by the logging package
var RawLogger = InitLogger(LogLevelString)

// InitLogger initializes a logger with the given log level string
func InitLogger(logLevelString string) *zap.SugaredLogger {
	logLevel, err := zap.ParseAtomicLevel(logLevelString)
	if err != nil {
		log.Fatalln("Invalid log level:", logLevelString)
	}

	config := zap.NewProductionConfig()
	config.EncoderConfig.TimeKey = "timestamp"
	config.Level = logLevel
	config.EncoderConfig.EncodeTime = zapcore.RFC3339TimeEncoder
	config.EncoderConfig.StacktraceKey = "" // to hide stacktrace info
	config.EncoderConfig.CallerKey = "caller"

	logger, err := config.Build()
	if err != nil {
		log.Fatal(err)
	}

	return logger.Sugar()
}

// InitLoggerWithPipelineName initializes a logger with a cluster-id specific child logger and a pipeline name
func InitLoggerWithPipelineName(logLevelString string, clusterID string, pipelineName string) *zap.SugaredLogger {
	logLevel, err := zap.ParseAtomicLevel(logLevelString)
	if err != nil {
		log.Fatalln("Invalid log level:", logLevelString)
	}

	config := zap.NewProductionConfig()
	config.EncoderConfig.TimeKey = "timestamp"
	config.Level = logLevel
	config.EncoderConfig.EncodeTime = zapcore.RFC3339TimeEncoder
	config.EncoderConfig.StacktraceKey = "" // to hide stacktrace info
	config.EncoderConfig.CallerKey = "caller"

	logger, err := config.Build()
	if err != nil {
		log.Fatal(err)
	}

	logger = logger.With(zap.Field{Key: "cluster_id", Type: zapcore.StringType, String: clusterID},
		zap.Field{Key: "pipeline_name", Type: zapcore.StringType, String: pipelineName})

	return logger.Sugar()
}

// InitConsoleLogger initializes a logger that outputs in console format using zapcore.NewConsoleEncoder
func InitConsoleLogger(logLevelString string) *zap.SugaredLogger {
	logLevel, err := zap.ParseAtomicLevel(logLevelString)
	if err != nil {
		log.Fatalln("Invalid log level:", logLevelString)
	}

	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = "timestamp"
	encoderConfig.EncodeTime = zapcore.RFC3339TimeEncoder
	encoderConfig.StacktraceKey = ""
	encoderConfig.CallerKey = "caller"

	consoleEncoder := zapcore.NewConsoleEncoder(encoderConfig)

	stdoutSyncer := zapcore.Lock(os.Stdout)
	stderrSyncer := zapcore.Lock(os.Stderr)

	// Core for Info and below to stdout
	stdoutCore := zapcore.NewCore(
		consoleEncoder,
		stdoutSyncer,
		zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
			return lvl < zapcore.ErrorLevel && lvl >= logLevel.Level()
		}),
	)

	// Core for Error and above to stderr
	stderrCore := zapcore.NewCore(
		consoleEncoder,
		stderrSyncer,
		zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
			return lvl >= zapcore.ErrorLevel && lvl >= logLevel.Level()
		}),
	)

	core := zapcore.NewTee(stdoutCore, stderrCore)
	logger := zap.New(core)
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

// getLogLevel returns the log level from the environment variable LOG_LEVEL
func getLogLevel() string {
	if envLogLevel, exists := os.LookupEnv("LOG_LEVEL"); exists {
		return envLogLevel
	}
	return "info"
}
