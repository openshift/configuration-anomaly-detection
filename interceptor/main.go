package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/openshift/configuration-anomaly-detection/interceptor/pkg/interceptor"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	zap "go.uber.org/zap"
	"knative.dev/pkg/signals"
)

const (
	HTTPPort     = 8080
	readTimeout  = 5 * time.Second
	writeTimeout = 20 * time.Second
	idleTimeout  = 60 * time.Second
)

var logger *zap.SugaredLogger

func main() {
	// set up signals so we handle the first shutdown signal gracefully
	ctx := signals.NewContext()

	service := interceptor.PagerDutyInterceptor{}
	var exists bool

	if service.PagerDutyToken, exists = os.LookupEnv("CAD_PD_TOKEN"); !exists {
		os.Exit(1)
	}

	if service.PagerDutySilentPolicy, exists = os.LookupEnv("CAD_SILENT_POLICY"); exists {
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.Handle("/", service)
	mux.HandleFunc("/ready", readinessHandler)

	srv := &http.Server{
		Addr: fmt.Sprintf(":%d", HTTPPort),
		BaseContext: func(listener net.Listener) context.Context {
			return ctx
		},
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
		Handler:      mux,
	}

	// Channel to listen for OS signals
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)

	// Run server in a goroutine
	go func() {
		logger.Infof("Listen and serve on port %d", HTTPPort)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("failed to start interceptors service: %v", err)
		}
	}()

	// Block until we receive a stop signal
	<-stop

	// Create a deadline to wait for.
	ctxShutDown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Attempt to gracefully shutdown the server
	if err := srv.Shutdown(ctxShutDown); err != nil {
		logger.Fatalf("server forced to shutdown: %v", err)
	}

	logger.Infof("Server exiting")
}

func init() {
	// read log level from environment variable
	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel == "" {
		logLevel = "info"
	}

	// set up logging
	logger = logging.InitLogger(logLevel)
}

func readinessHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}
