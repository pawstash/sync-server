package syncapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const protocolVersion = 1
const maxBody = 2 << 20
const maxCiphertextBytes = 64 << 10 // 64 KB per record ciphertext limit

var (
	opaqueID = regexp.MustCompile(`^[A-Za-z0-9_-]{8,128}$`)
	recordID = regexp.MustCompile(`^[A-Za-z0-9_:.@/-]{1,256}$`)
)

type Options struct {
	MaxRecordsPerAccount int
	MaxDevicesPerAccount int
	RetentionDays        int
	RetentionInterval    time.Duration
	RateLimitEnabled     bool
}

func DefaultOptions() Options {
	return Options{
		MaxRecordsPerAccount: 50000,
		MaxDevicesPerAccount: 25,
		RetentionDays:        90,
		RetentionInterval:    1 * time.Hour,
		RateLimitEnabled:     true,
	}
}

type Server struct {
	db          *sql.DB
	mux         *http.ServeMux
	opts        Options
	ipLimiter   *rateLimiter
	authLimiter *rateLimiter
	pushLimiter *rateLimiter
	stopCh      chan struct{}
}

type contextKey string

const accountKey contextKey = "account"
const deviceKey contextKey = "device"

type accountRequest struct {
	AccountID          string          `json:"account_id"`
	AuthToken          string          `json:"auth_token"`
	KDF                json.RawMessage `json:"kdf"`
	EncryptedKeyBundle string          `json:"encrypted_key_bundle"`
	Nonce              string          `json:"nonce"`
}
type sessionRequest struct {
	AccountID string `json:"account_id"`
	AuthToken string `json:"auth_token"`
	DeviceID  string `json:"device_id,omitempty"`
}
type deviceRequest struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Platform  string `json:"platform"`
	PublicKey string `json:"public_key,omitempty"`
}
type recordEnvelope struct {
	RecordID         string `json:"record_id"`
	Kind             string `json:"kind"`
	ExpectedRevision int64  `json:"expected_revision"`
	DeviceID         string `json:"device_id"`
	Ciphertext       string `json:"ciphertext"`
	Nonce            string `json:"nonce"`
	Tombstone        bool   `json:"tombstone"`
}
type pushRequest struct {
	ProtocolVersion int              `json:"protocol_version"`
	Records         []recordEnvelope `json:"records"`
}
type acceptedRecord struct {
	RecordID string `json:"record_id"`
	Revision int64  `json:"revision"`
	Position int64  `json:"position"`
}
type pushResponse struct {
	Cursor   int64            `json:"cursor"`
	Accepted []acceptedRecord `json:"accepted"`
}

func New(path string) (*Server, error) {
	return NewWithOptions(path, DefaultOptions())
}

func NewWithOptions(path string, opts Options) (*Server, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err = migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	stopCh := make(chan struct{})
	s := &Server{
		db:          db,
		mux:         http.NewServeMux(),
		opts:        opts,
		ipLimiter:   newRateLimiter(5.0, 30.0), // 300 req/min general burst
		authLimiter: newRateLimiter(0.5, 10.0), // 30 req/min for auth
		pushLimiter: newRateLimiter(2.0, 20.0), // 120 req/min for record push
		stopCh:      stopCh,
	}
	startRetentionWorker(db, opts.RetentionInterval, opts.RetentionDays, stopCh)
	s.routes()
	return s, nil
}

func (s *Server) Close() error {
	select {
	case <-s.stopCh:
	default:
		close(s.stopCh)
	}
	if s.ipLimiter != nil {
		s.ipLimiter.close()
	}
	if s.authLimiter != nil {
		s.authLimiter.close()
	}
	if s.pushLimiter != nil {
		s.pushLimiter.close()
	}
	return s.db.Close()
}

func (s *Server) Handler() http.Handler {
	return s.logger(securityHeaders(s.mux))
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /v1/health", s.health)
	s.mux.HandleFunc("POST /v1/accounts", s.createAccount)
	s.mux.HandleFunc("GET /v1/accounts/{account_id}/bundle", s.getBundle)
	s.mux.Handle("PUT /v1/accounts/{account_id}/bundle", s.auth(true, http.HandlerFunc(s.replaceBundle)))
	s.mux.HandleFunc("POST /v1/sessions", s.createSession)
	s.mux.Handle("POST /v1/devices", s.auth(false, http.HandlerFunc(s.registerDevice)))
	s.mux.Handle("GET /v1/devices", s.auth(true, http.HandlerFunc(s.listDevices)))
	s.mux.Handle("DELETE /v1/devices/{device_id}", s.auth(true, http.HandlerFunc(s.revokeDevice)))
	s.mux.Handle("GET /v1/changes", s.auth(true, http.HandlerFunc(s.pullChanges)))
	s.mux.Handle("POST /v1/records:push", s.auth(true, http.HandlerFunc(s.pushRecords)))
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"status": "ok", "protocol_versions": []int{protocolVersion}})
}

func (s *Server) createAccount(w http.ResponseWriter, r *http.Request) {
	if s.opts.RateLimitEnabled && !s.authLimiter.allow(clientIP(r)) {
		problem(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}
	var input accountRequest
	if !decode(w, r, &input) {
		return
	}
	if !validAccount(input) {
		problem(w, 400, "invalid account envelope")
		return
	}
	_, err := s.db.Exec(`INSERT INTO accounts(id,auth_token_hash,kdf_json,encrypted_key_bundle,nonce) VALUES(?,?,?,?,?)`, input.AccountID, tokenHash(input.AuthToken), string(input.KDF), input.EncryptedKeyBundle, input.Nonce)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			problem(w, 409, "account already exists")
		} else {
			problem(w, 500, "database error")
		}
		return
	}
	writeJSON(w, 201, map[string]any{"account_id": input.AccountID, "protocol_version": protocolVersion})
}

func (s *Server) getBundle(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("account_id")
	var kdf, bundle, nonce string
	err := s.db.QueryRow(`SELECT kdf_json,encrypted_key_bundle,nonce FROM accounts WHERE id=?`, id).Scan(&kdf, &bundle, &nonce)
	if errors.Is(err, sql.ErrNoRows) {
		problem(w, 404, "account not found")
		return
	}
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	var kdfValue any
	if json.Unmarshal([]byte(kdf), &kdfValue) != nil {
		problem(w, 500, "stored envelope is invalid")
		return
	}
	writeJSON(w, 200, map[string]any{"account_id": id, "kdf": kdfValue, "encrypted_key_bundle": bundle, "nonce": nonce})
}

func (s *Server) replaceBundle(w http.ResponseWriter, r *http.Request) {
	account := accountFrom(r)
	if r.PathValue("account_id") != account {
		problem(w, 403, "wrong account")
		return
	}
	var input struct {
		KDF                json.RawMessage `json:"kdf"`
		EncryptedKeyBundle string          `json:"encrypted_key_bundle"`
		Nonce              string          `json:"nonce"`
	}
	if !decode(w, r, &input) {
		return
	}
	if len(input.KDF) == 0 || !validBlob(input.EncryptedKeyBundle, 64, maxCiphertextBytes) || !validBlob(input.Nonce, 12, 128) {
		problem(w, 400, "invalid encrypted bundle")
		return
	}
	if _, err := s.db.Exec(`UPDATE accounts SET kdf_json=?,encrypted_key_bundle=?,nonce=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`, string(input.KDF), input.EncryptedKeyBundle, input.Nonce, account); err != nil {
		problem(w, 500, "database error")
		return
	}
	w.WriteHeader(204)
}

func (s *Server) createSession(w http.ResponseWriter, r *http.Request) {
	if s.opts.RateLimitEnabled && !s.authLimiter.allow(clientIP(r)) {
		problem(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}
	var input sessionRequest
	if !decode(w, r, &input) {
		return
	}
	var expected string
	if s.db.QueryRow(`SELECT auth_token_hash FROM accounts WHERE id=?`, input.AccountID).Scan(&expected) != nil || expected != tokenHash(input.AuthToken) {
		problem(w, 401, "invalid credentials")
		return
	}
	if input.DeviceID != "" {
		var active int
		if s.db.QueryRow(`SELECT 1 FROM devices WHERE account_id=? AND id=? AND revoked_at IS NULL`, input.AccountID, input.DeviceID).Scan(&active) != nil {
			problem(w, 401, "device is unknown or revoked")
			return
		}
	}
	raw, err := randomToken()
	if err != nil {
		problem(w, 500, "random source unavailable")
		return
	}
	expires := time.Now().UTC().Add(30 * 24 * time.Hour)
	if input.DeviceID == "" {
		expires = time.Now().UTC().Add(10 * time.Minute)
	}
	var device any
	if input.DeviceID != "" {
		device = input.DeviceID
	}
	if _, err = s.db.Exec(`INSERT INTO sessions(token_hash,account_id,device_id,expires_at) VALUES(?,?,?,?)`, tokenHash(raw), input.AccountID, device, expires.Format(time.RFC3339)); err != nil {
		problem(w, 500, "database error")
		return
	}
	writeJSON(w, 201, map[string]any{"token": raw, "expires_at": expires, "protocol_version": protocolVersion})
}

func (s *Server) registerDevice(w http.ResponseWriter, r *http.Request) {
	var input deviceRequest
	if !decode(w, r, &input) {
		return
	}
	if !opaqueID.MatchString(input.ID) || len(input.Name) > 100 || len(input.Platform) > 40 {
		problem(w, 400, "invalid device")
		return
	}
	account := accountFrom(r)

	// Check device quota for account
	var deviceCount int
	if err := s.db.QueryRow(`SELECT COUNT(1) FROM devices WHERE account_id=? AND revoked_at IS NULL AND id!=?`, account, input.ID).Scan(&deviceCount); err == nil {
		if deviceCount >= s.opts.MaxDevicesPerAccount {
			problem(w, http.StatusBadRequest, fmt.Sprintf("device quota exceeded (max %d active devices)", s.opts.MaxDevicesPerAccount))
			return
		}
	}

	_, err := s.db.Exec(`INSERT INTO devices(account_id,id,name,platform,public_key) VALUES(?,?,?,?,?) ON CONFLICT(account_id,id) DO UPDATE SET name=excluded.name,platform=excluded.platform,public_key=excluded.public_key,revoked_at=NULL`, account, input.ID, input.Name, input.Platform, input.PublicKey)
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	writeJSON(w, 201, input)
}

func (s *Server) listDevices(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query(`SELECT id,name,platform,created_at,revoked_at FROM devices WHERE account_id=? ORDER BY created_at DESC,id`, accountFrom(r))
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	defer rows.Close()
	devices := make([]map[string]any, 0)
	for rows.Next() {
		var id, name, platform, created string
		var revoked sql.NullString
		if rows.Scan(&id, &name, &platform, &created, &revoked) != nil {
			problem(w, 500, "database error")
			return
		}
		var revokedAt any
		if revoked.Valid {
			revokedAt = revoked.String
		}
		devices = append(devices, map[string]any{"id": id, "name": name, "platform": platform, "created_at": created, "revoked_at": revokedAt})
	}
	if err := rows.Err(); err != nil {
		problem(w, 500, "database error")
		return
	}
	writeJSON(w, 200, map[string]any{"devices": devices})
}

func (s *Server) revokeDevice(w http.ResponseWriter, r *http.Request) {
	result, err := s.db.Exec(`UPDATE devices SET revoked_at=CURRENT_TIMESTAMP WHERE account_id=? AND id=? AND revoked_at IS NULL`, accountFrom(r), r.PathValue("device_id"))
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		problem(w, 404, "device not found")
		return
	}
	_, _ = s.db.Exec(`DELETE FROM sessions WHERE account_id=? AND device_id=?`, accountFrom(r), r.PathValue("device_id"))
	w.WriteHeader(204)
}

func (s *Server) pullChanges(w http.ResponseWriter, r *http.Request) {
	after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit < 1 {
		limit = 200
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := s.db.Query(`SELECT position,record_id,revision,kind,device_id,ciphertext,nonce,tombstone,created_at FROM changes WHERE account_id=? AND position>? ORDER BY position LIMIT ?`, accountFrom(r), after, limit)
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	defer rows.Close()
	changes := make([]map[string]any, 0)
	cursor := after
	for rows.Next() {
		var p, rev int64
		var id, kind, device, cipher, nonce, created string
		var tomb bool
		if rows.Scan(&p, &id, &rev, &kind, &device, &cipher, &nonce, &tomb, &created) != nil {
			problem(w, 500, "database error")
			return
		}
		cursor = p
		changes = append(changes, map[string]any{"position": p, "record_id": id, "revision": rev, "kind": kind, "device_id": device, "ciphertext": cipher, "nonce": nonce, "tombstone": tomb, "created_at": created})
	}
	writeJSON(w, 200, map[string]any{"cursor": cursor, "changes": changes})
}

func (s *Server) pushRecords(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("Idempotency-Key")
	if !opaqueID.MatchString(key) {
		problem(w, 400, "invalid or missing idempotency key")
		return
	}
	account := accountFrom(r)
	device := deviceFrom(r)

	if s.opts.RateLimitEnabled && !s.pushLimiter.allow(account) {
		problem(w, http.StatusTooManyRequests, "rate limit exceeded for push")
		return
	}

	var cached []byte
	if s.db.QueryRow(`SELECT response_json FROM idempotency_keys WHERE account_id=? AND key=?`, account, key).Scan(&cached) == nil {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(cached)
		return
	}
	var input pushRequest
	if !decode(w, r, &input) {
		return
	}
	if input.ProtocolVersion != protocolVersion || len(input.Records) == 0 || len(input.Records) > 100 {
		problem(w, 400, "unsupported protocol or batch size")
		return
	}
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	defer tx.Rollback()

	// Check total active records quota for account
	var currentActiveRecords int
	if err := tx.QueryRow(`SELECT COUNT(1) FROM records WHERE account_id=? AND tombstone=0`, account).Scan(&currentActiveRecords); err == nil {
		newNonTombstoneCount := 0
		for _, rec := range input.Records {
			if !rec.Tombstone && rec.ExpectedRevision == 0 {
				newNonTombstoneCount++
			}
		}
		if currentActiveRecords+newNonTombstoneCount > s.opts.MaxRecordsPerAccount {
			problem(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("account record quota exceeded (max %d records)", s.opts.MaxRecordsPerAccount))
			return
		}
	}

	for _, record := range input.Records {
		if !validRecord(record) {
			problem(w, 400, "invalid record envelope")
			return
		}
		if record.DeviceID != device {
			problem(w, 403, "record device does not match session")
			return
		}
		var rev int64
		err = tx.QueryRow(`SELECT revision FROM records WHERE account_id=? AND record_id=?`, account, record.RecordID).Scan(&rev)
		if errors.Is(err, sql.ErrNoRows) {
			rev = 0
		} else if err != nil {
			problem(w, 500, "database error")
			return
		}
		if rev != record.ExpectedRevision {
			problem(w, 409, fmt.Sprintf("revision conflict for %s: current=%d", record.RecordID, rev))
			return
		}
	}
	accepted := make([]acceptedRecord, 0, len(input.Records))
	var cursor int64
	for _, record := range input.Records {
		rev := record.ExpectedRevision + 1
		_, err = tx.Exec(`INSERT INTO records(account_id,record_id,revision,kind,device_id,ciphertext,nonce,tombstone) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(account_id,record_id) DO UPDATE SET revision=excluded.revision,kind=excluded.kind,device_id=excluded.device_id,ciphertext=excluded.ciphertext,nonce=excluded.nonce,tombstone=excluded.tombstone,updated_at=CURRENT_TIMESTAMP`, account, record.RecordID, rev, record.Kind, record.DeviceID, record.Ciphertext, record.Nonce, record.Tombstone)
		if err != nil {
			problem(w, 500, "database error")
			return
		}
		result, err := tx.Exec(`INSERT INTO changes(account_id,record_id,revision,kind,device_id,ciphertext,nonce,tombstone) VALUES(?,?,?,?,?,?,?,?)`, account, record.RecordID, rev, record.Kind, record.DeviceID, record.Ciphertext, record.Nonce, record.Tombstone)
		if err != nil {
			problem(w, 500, "database error")
			return
		}
		cursor, _ = result.LastInsertId()
		accepted = append(accepted, acceptedRecord{record.RecordID, rev, cursor})
	}
	response := pushResponse{cursor, accepted}
	encoded, _ := json.Marshal(response)
	if _, err = tx.Exec(`INSERT INTO idempotency_keys(account_id,key,response_json) VALUES(?,?,?)`, account, key, encoded); err != nil {
		problem(w, 500, "database error")
		return
	}
	if err = tx.Commit(); err != nil {
		problem(w, 500, "database error")
		return
	}
	writeJSON(w, 200, response)
}

func (s *Server) auth(requireDevice bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := strings.TrimSpace(r.Header.Get("Authorization"))
		if !strings.HasPrefix(header, "Bearer ") {
			problem(w, 401, "bearer session required")
			return
		}
		var account, expires string
		var device sql.NullString
		err := s.db.QueryRow(`SELECT account_id,device_id,expires_at FROM sessions WHERE token_hash=?`, tokenHash(strings.TrimPrefix(header, "Bearer "))).Scan(&account, &device, &expires)
		deadline, _ := time.Parse(time.RFC3339, expires)
		if err != nil || time.Now().After(deadline) {
			problem(w, 401, "invalid or expired session")
			return
		}
		if requireDevice {
			if !device.Valid {
				problem(w, 401, "device-bound session required")
				return
			}
			var active int
			if s.db.QueryRow(`SELECT 1 FROM devices WHERE account_id=? AND id=? AND revoked_at IS NULL`, account, device.String).Scan(&active) != nil {
				problem(w, 401, "device is revoked")
				return
			}
		}
		ctx := context.WithValue(r.Context(), accountKey, account)
		if device.Valid {
			ctx = context.WithValue(ctx, deviceKey, device.String)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

func (s *Server) logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/health" {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		lrw := &loggingResponseWriter{ResponseWriter: w, statusCode: 200}
		next.ServeHTTP(lrw, r)
		duration := time.Since(start)

		account := accountFrom(r)
		if account == "" {
			account = "-"
		}
		ip := clientIP(r)
		log.Printf("[sync] %s %s status=%d dur=%s ip=%s account=%s", r.Method, r.URL.Path, lrw.statusCode, duration, ip, account)
	})
}

func deviceFrom(r *http.Request) string {
	value, _ := r.Context().Value(deviceKey).(string)
	return value
}
func accountFrom(r *http.Request) string {
	value, _ := r.Context().Value(accountKey).(string)
	return value
}
func validAccount(v accountRequest) bool {
	return opaqueID.MatchString(v.AccountID) && len(v.AuthToken) >= 32 && len(v.KDF) > 2 && validBlob(v.EncryptedKeyBundle, 64, maxCiphertextBytes) && validBlob(v.Nonce, 12, 128)
}
func validRecord(v recordEnvelope) bool {
	return recordID.MatchString(v.RecordID) && opaqueID.MatchString(v.DeviceID) && v.ExpectedRevision >= 0 && len(v.Kind) > 0 && len(v.Kind) <= 40 && validBlob(v.Ciphertext, 16, maxCiphertextBytes) && validBlob(v.Nonce, 12, 128)
}
func validBlob(value string, min, max int) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) >= min && len(decoded) <= max
}
func tokenHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
func randomToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b), err
}
func decode(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		problem(w, 400, "invalid JSON body")
		return false
	}
	if err := d.Decode(&struct{}{}); err != io.EOF {
		problem(w, 400, "body must contain one JSON value")
		return false
	}
	return true
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func problem(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"error": message})
}
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

const schema = `PRAGMA journal_mode=WAL;PRAGMA foreign_keys=ON;PRAGMA busy_timeout=5000;
CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY,applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS accounts(id TEXT PRIMARY KEY,auth_token_hash TEXT NOT NULL,kdf_json TEXT NOT NULL,encrypted_key_bundle TEXT NOT NULL,nonce TEXT NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,device_id TEXT,expires_at TEXT NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);CREATE INDEX IF NOT EXISTS idx_sessions_account ON sessions(account_id,expires_at);
CREATE TABLE IF NOT EXISTS devices(account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,id TEXT NOT NULL,name TEXT NOT NULL,platform TEXT NOT NULL,public_key TEXT,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,revoked_at TEXT,PRIMARY KEY(account_id,id));
CREATE TABLE IF NOT EXISTS records(account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,record_id TEXT NOT NULL,revision INTEGER NOT NULL,kind TEXT NOT NULL,device_id TEXT NOT NULL,ciphertext TEXT NOT NULL,nonce TEXT NOT NULL,tombstone INTEGER NOT NULL DEFAULT 0,updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,PRIMARY KEY(account_id,record_id));
CREATE TABLE IF NOT EXISTS changes(position INTEGER PRIMARY KEY AUTOINCREMENT,account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,record_id TEXT NOT NULL,revision INTEGER NOT NULL,kind TEXT NOT NULL,device_id TEXT NOT NULL,ciphertext TEXT NOT NULL,nonce TEXT NOT NULL,tombstone INTEGER NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);CREATE INDEX IF NOT EXISTS idx_changes_pull ON changes(account_id,position);
CREATE TABLE IF NOT EXISTS idempotency_keys(account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,key TEXT NOT NULL,response_json BLOB NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,PRIMARY KEY(account_id,key));`

func migrate(db *sql.DB) error {
	if _, err := db.Exec(schema); err != nil {
		return err
	}
	rows, err := db.Query(`PRAGMA table_info(sessions)`)
	if err != nil {
		return err
	}
	hasDeviceID := false
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			rows.Close()
			return err
		}
		if name == "device_id" {
			hasDeviceID = true
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if !hasDeviceID {
		if _, err := db.Exec(`ALTER TABLE sessions ADD COLUMN device_id TEXT`); err != nil {
			return err
		}
	}
	_, err = db.Exec(`INSERT OR IGNORE INTO schema_migrations(version) VALUES(1),(2)`)
	return err
}
