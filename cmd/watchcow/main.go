package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/go-chi/chi/v5"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"watchcow/internal/app"
	"watchcow/internal/cgi"
	"watchcow/internal/docker"
	"watchcow/internal/reverse"
	"watchcow/internal/server"
)

// fallbackSocketPath is used when TRIM_PKGVAR is not set
const fallbackSocketPath = "/tmp/watchcow-r/watchcow.sock"

// getDefaultSocketPath returns socket path based on environment
func getDefaultSocketPath() string {
	if pkgVar := os.Getenv("TRIM_PKGVAR"); pkgVar != "" {
		return filepath.Join(pkgVar, "watchcow.sock")
	}
	return fallbackSocketPath
}

func main() {
	// Define flags
	mode := flag.String("mode", "server", "Run mode: server, cgi, init, disable or rollback")
	socketPath := flag.String("socket", "", "Unix socket path (default: $TRIM_PKGVAR/watchcow.sock or /tmp/watchcow-r/watchcow.sock)")
	debug := flag.Bool("debug", false, "Enable debug mode")
	cgiApp := flag.String("cgi-app", "", "Installed package scope for CGI requests")
	flag.Parse()

	// Use default socket path if not specified
	actualSocketPath := *socketPath
	if actualSocketPath == "" {
		actualSocketPath = getDefaultSocketPath()
	}

	switch *mode {
	case "init":
		if err := reverse.Initialize(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "disable", "rollback":
		m, err := reverse.New(reverse.SettingsDir(), app.NewRegistry())
		if err == nil {
			if *mode == "rollback" {
				err = m.Rollback()
			} else {
				err = m.Disable()
			}
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "server":
		runServerMode(actualSocketPath, *debug)
	case "cgi":
		runCGIMode(actualSocketPath, *cgiApp)
	default:
		fmt.Fprintf(os.Stderr, "Unknown mode: %s (use 'server' or 'cgi')\n", *mode)
		os.Exit(1)
	}
}

// runCGIMode handles CGI requests by proxying to Unix socket server
func runCGIMode(socketPath, scope string) {
	cgi.RunCGI(socketPath, scope)
}

// runServerMode runs the Docker monitoring daemon with HTTP server
func runServerMode(socketPath string, debug bool) {
	// Configure slog
	var logLevel slog.Level
	if debug {
		logLevel = slog.LevelDebug
	} else {
		logLevel = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: logLevel,
	}
	logHandler := slog.NewTextHandler(os.Stdout, opts)
	logger := slog.New(logHandler)
	slog.SetDefault(logger)

	slog.Info("Watchcow_R - fnOS Docker apps with native reverse proxy")
	slog.Info("========================================")

	// Create context with signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigChan)

	// Step 1: Create Docker monitor first
	monitor, err := docker.NewMonitor()
	if err != nil {
		slog.Error("Failed to create Docker monitor", "error", err)
		os.Exit(1)
	}
	monitor.AdoptExisting = true
	proxy, err := reverse.New(reverse.SettingsDir(), monitor.Registry())
	if err != nil {
		slog.Error("Reverse proxy settings", "error", err)
		os.Exit(1)
	}
	abort := func(message string, err error) {
		slog.Error(message, "error", err)
		monitor.Stop()
		if restoreErr := proxy.Rollback(); restoreErr != nil {
			slog.Error("Migration rollback needs attention", "error", restoreErr)
		}
		os.Exit(1)
	}
	if err := proxy.Prepare(); err != nil {
		if errors.Is(err, reverse.ErrExtensionConsent) {
			slog.Info("Waiting for explicit Nginx extension opt-in")
			if waitForSetup(ctx, sigChan, socketPath, proxy) {
				monitor.Stop()
				signal.Stop(sigChan)
				runServerMode(socketPath, debug)
			} else {
				monitor.Stop()
			}
			return
		}
		abort("Migration preparation", err)
	}
	_ = os.Setenv("WATCHCOW_R_ACTIVE", "1")
	// Complete a previously interrupted desktop reinstall before the Docker
	// monitor can mistake its temporarily missing package for a fresh install.
	if err := proxy.RecoverDesktopPending(ctx); err != nil {
		slog.Error("Recover interrupted desktop registration; backups retained", "error", err)
		monitor.Stop()
		return
	}

	// Step 2: Create dashboard storage and connect to monitor
	dashboardStorage, err := server.NewDashboardStorage()
	if err != nil {
		abort("Failed to create dashboard storage", err)
	}

	// Connect storage to monitor for config lookup
	monitor.SetConfigProvider(dashboardStorage)
	if err := server.AdoptInstalled(ctx, monitor, dashboardStorage, "/var/apps"); err != nil {
		abort("Import installed apps", err)
	}
	proxy.LiveState = func(ctx context.Context) (map[string]bool, error) {
		items, err := monitor.Inventory(ctx)
		if err != nil {
			return nil, err
		}
		states := map[string]bool{}
		for _, item := range items {
			states[item.Name] = item.State == "running"
		}
		return states, nil
	}
	// Resolve actual Docker host bindings; loopback is preferred for wildcard
	// bindings, but services bound to a specific local address remain usable.
	proxy.Resolve = monitor.ResolveWebUpstream

	// Step 3: Create HTTP handlers and router
	redirectHandler := server.NewRedirectHandler(monitor.Registry())

	dashboardHandler, err := server.NewDashboardHandler(dashboardStorage, monitor, monitor)
	if err != nil {
		abort("Failed to create dashboard handler", err)
	}

	router := server.NewRouter(redirectHandler, dashboardHandler, func(r chi.Router) {
		r.Get("/proxy/*", proxy.Launch)
		r.Get("/reverse", proxy.Panel)
		r.Post("/reverse", proxy.Panel)
	})

	// Step 4: Create server with monitor injected
	srv := server.New(socketPath, router, monitor)

	// Step 4: Start server (which will start monitor after socket is ready)
	go func() {
		if err := srv.Start(ctx); err != nil {
			slog.Error("Server error", "error", err)
			cancel()
		}
	}()

	// Wait for server to be ready
	select {
	case <-srv.Ready():
	case <-ctx.Done():
		abort("Admin server failed to start", ctx.Err())
	}
	proxyCtx, stopProxy := context.WithCancel(ctx)
	proxyDone := make(chan struct{})
	go func() {
		defer close(proxyDone)
		if err := proxy.Reconcile(proxyCtx); err != nil {
			slog.Error("Initial reverse proxy apply", "error", err)
		}
		proxy.Run(proxyCtx)
	}()
	desktopDone := make(chan struct{})
	go func() {
		defer close(desktopDone)
		proxy.RunDesktopSync(proxyCtx)
	}()
	iconsDone := make(chan struct{})
	go func() { defer close(iconsDone); proxy.RunIcons(proxyCtx) }()

	slog.Info("Monitoring started (Press Ctrl+C to stop)")
	slog.Info("")
	slog.Info("To enable fnOS app generation for a container, add these labels:")
	slog.Info("  watchcow.enable: \"true\"")
	slog.Info("  watchcow.display_name: \"Your App Name\"")
	slog.Info("  watchcow.service_port: \"8080\"")
	slog.Info("")

	// Wait for shutdown signal
	select {
	case <-sigChan:
	case <-ctx.Done():
	}
	slog.Info("Shutting down...")

	// Stop server (which stops monitor too)
	stopProxy()
	<-iconsDone
	<-desktopDone
	<-proxyDone
	if err := proxy.Disable(); err != nil {
		slog.Error("Disable proxy", "error", err)
	}
	shutdownCtx, done := context.WithTimeout(context.Background(), 20*time.Second)
	defer done()
	srv.Stop(shutdownCtx)
}

func waitForSetup(ctx context.Context, signals <-chan os.Signal, socket string, proxy *reverse.Manager) bool {
	setupCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	srv := server.New(socket, http.HandlerFunc(proxy.SetupPage), nil)
	failed := make(chan error, 1)
	go func() { failed <- srv.Start(setupCtx) }()
	defer srv.Stop(context.Background())
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-signals:
			return false
		case err := <-failed:
			slog.Error("Setup server stopped", "error", err)
			return false
		case <-ticker.C:
			settings, err := reverse.Load(reverse.SettingsDir())
			if err == nil && settings.NativeExtensions {
				cancel()
				srv.Stop(context.Background())
				return true
			}
		}
	}
}
