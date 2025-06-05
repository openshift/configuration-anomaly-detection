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
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"knative.dev/pkg/signals"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

const (
	HTTPPort     = 8080
	readTimeout  = 5 * time.Second
	writeTimeout = 20 * time.Second
	idleTimeout  = 60 * time.Second
)

var logger = logging.InitLogger(logging.LogLevelString, "")

func main() {
	// set up signals so we handle the first shutdown signal gracefully
	ctx := signals.NewContext()

	stats := interceptor.CreateInterceptorStats()
	mux := http.NewServeMux()
	mux.Handle("/", interceptor.CreateInterceptorHandler(stats))
	mux.HandleFunc("/ready", readinessHandler)
	interceptor.CreateAndRegisterMetricsCollector(stats)
	mux.Handle("/metrics", promhttp.HandlerFor(metrics.Registry, promhttp.HandlerOpts{Registry: metrics.Registry}))

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

func readinessHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}
