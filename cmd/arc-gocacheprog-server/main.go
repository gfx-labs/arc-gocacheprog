// Command arc-gocacheprog-server is the HTTP cache backend for arc-gocacheprog.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/gfx-labs/arc-gocacheprog/internal/server"
	"github.com/gfx-labs/arc-gocacheprog/internal/telemetry"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", envOr("ARC_GOCACHE_CONFIG", "config.yaml"), "path to YAML config")
	gcOnce := flag.Bool("gc-once", false, "run one GC pass and exit")
	debug := flag.Bool("debug", false, "debug logging")
	flag.Parse()

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(log)

	cfg, err := server.LoadConfig(*configPath)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Before the store and S3 client, which capture the global providers.
	shutdownTelemetry, err := telemetry.Setup(ctx, "arc-gocacheprog-server", version())
	if err != nil {
		return fmt.Errorf("telemetry: %w", err)
	}
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := shutdownTelemetry(sctx); err != nil {
			log.Warn("telemetry shutdown", "err", err)
		}
	}()

	store, err := server.OpenStore(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer store.Close()
	if err := store.Migrate(ctx); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	s3c, err := server.NewS3Client(ctx, cfg.S3)
	if err != nil {
		return err
	}
	blobs := server.NewBlobStore(s3c, cfg.S3.Bucket, cfg.S3.Prefix)
	if cfg.S3.CreateBucket {
		if err := blobs.EnsureBucket(ctx); err != nil {
			return err
		}
	}

	gc := server.NewGC(cfg.GC, store, blobs, log)
	if *gcOnce {
		st, ran, err := gc.RunLocked(ctx)
		if err != nil {
			return err
		}
		log.Info("gc", "ran", ran, "stats", st)
		return nil
	}

	auth, err := server.NewAuthenticator(cfg.Auth)
	if err != nil {
		return err
	}
	srv := server.New(cfg, store, blobs, auth, log)

	if cfg.GC.Enabled {
		go gc.Loop(ctx)
	}

	hs := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       cfg.Storage.RequestTimeout,
		WriteTimeout:      cfg.Storage.RequestTimeout,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelError),
	}
	errc := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.Listen)
		errc <- hs.ListenAndServe()
	}()
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return hs.Shutdown(shutdownCtx)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func version() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	if v := bi.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	for _, s := range bi.Settings {
		if s.Key == "vcs.revision" {
			return s.Value
		}
	}
	return "(devel)"
}
