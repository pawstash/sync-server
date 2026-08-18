package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/pawstash/sync-server/internal/syncapi"
)

func main() {
	addr := env("PAWSTASH_SYNC_ADDR", "127.0.0.1:8787")
	dbPath := env("PAWSTASH_SYNC_DB", filepath.Join("data", "sync.db"))
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
		log.Fatal(err)
	}

	opts := syncapi.DefaultOptions()
	if v, err := strconv.Atoi(os.Getenv("PAWSTASH_SYNC_MAX_RECORDS")); err == nil && v > 0 {
		opts.MaxRecordsPerAccount = v
	}
	if v, err := strconv.Atoi(os.Getenv("PAWSTASH_SYNC_MAX_DEVICES")); err == nil && v > 0 {
		opts.MaxDevicesPerAccount = v
	}
	if v, err := strconv.Atoi(os.Getenv("PAWSTASH_SYNC_RETENTION_DAYS")); err == nil && v > 0 {
		opts.RetentionDays = v
	}
	if v := os.Getenv("PAWSTASH_SYNC_RATE_LIMIT"); v == "false" || v == "0" {
		opts.RateLimitEnabled = false
	}

	server, err := syncapi.NewWithOptions(dbPath, opts)
	if err != nil {
		log.Fatal(err)
	}
	defer server.Close()

	httpServer := &http.Server{
		Addr:              addr,
		Handler:           server.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    32 << 10,
	}

	stopped := make(chan os.Signal, 1)
	signal.Notify(stopped, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stopped
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(ctx); err != nil {
			log.Printf("graceful shutdown failed: %v", err)
		}
	}()

	log.Printf("pawstash-sync listening on %s (max_records=%d, retention_days=%d)", addr, opts.MaxRecordsPerAccount, opts.RetentionDays)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
