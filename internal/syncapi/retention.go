package syncapi

import (
	"database/sql"
	"fmt"
	"log"
	"time"
)

func RunRetention(db *sql.DB, retentionDays int) error {
	if retentionDays < 7 {
		retentionDays = 7
	}

	// 1. Clean expired sessions
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := db.Exec(`DELETE FROM sessions WHERE expires_at <= ?`, now)
	if err == nil {
		if count, _ := res.RowsAffected(); count > 0 {
			log.Printf("[retention] pruned %d expired sessions", count)
		}
	}

	// 2. Clean old idempotency keys older than 7 days
	res, err = db.Exec(`DELETE FROM idempotency_keys WHERE created_at <= datetime('now', '-7 days')`)
	if err == nil {
		if count, _ := res.RowsAffected(); count > 0 {
			log.Printf("[retention] pruned %d stale idempotency keys", count)
		}
	}

	// 3. Clean old change log entries older than retentionDays
	daysQuery := fmt.Sprintf("-%d days", retentionDays)
	res, err = db.Exec(`DELETE FROM changes WHERE created_at <= datetime('now', ?)`, daysQuery)
	if err == nil {
		if count, _ := res.RowsAffected(); count > 0 {
			log.Printf("[retention] pruned %d old change log entries (>%d days)", count, retentionDays)
		}
	}

	// 4. Run SQLite optimization to maintain index efficiency and bounded disk
	_, _ = db.Exec(`PRAGMA optimize;`)
	return nil
}

func startRetentionWorker(db *sql.DB, interval time.Duration, retentionDays int, stop chan struct{}) {
	// Run once immediately on startup
	_ = RunRetention(db, retentionDays)

	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				_ = RunRetention(db, retentionDays)
			case <-stop:
				return
			}
		}
	}()
}
