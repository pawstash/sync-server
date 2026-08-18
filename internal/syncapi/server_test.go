package syncapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestEncryptedRecordRoundTripAndConflict(t *testing.T) {
	server, err := New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	handler := server.Handler()
	accountID := "account_test_01"
	authToken := strings.Repeat("a", 32)
	request(t, handler, "POST", "/v1/accounts", "", "", map[string]any{
		"account_id": accountID, "auth_token": authToken,
		"kdf":                  map[string]any{"algorithm": "argon2id", "memory_kib": 65536},
		"encrypted_key_bundle": blob(96), "nonce": blob(24),
	}, http.StatusCreated)

	session := request(t, handler, "POST", "/v1/sessions", "", "", map[string]any{
		"account_id": accountID, "auth_token": authToken,
	}, http.StatusCreated)
	token := session["token"].(string)
	deviceID := "device_test_01"
	request(t, handler, "POST", "/v1/devices", token, "", map[string]any{
		"id": deviceID, "name": "Desktop", "platform": "windows",
	}, http.StatusCreated)
	bound := request(t, handler, "POST", "/v1/sessions", "", "", map[string]any{
		"account_id": accountID, "auth_token": authToken, "device_id": deviceID,
	}, http.StatusCreated)
	token = bound["token"].(string)

	batch := map[string]any{"protocol_version": 1, "records": []map[string]any{{
		"record_id": "record_test_01", "kind": "library_entry", "expected_revision": 0,
		"device_id": "device_test_01", "ciphertext": blob(64), "nonce": blob(24), "tombstone": false,
	}}}
	first := request(t, handler, "POST", "/v1/records:push", token, "request_test_01", batch, http.StatusOK)
	if first["cursor"].(float64) != 1 {
		t.Fatalf("unexpected cursor: %#v", first)
	}
	replayed := request(t, handler, "POST", "/v1/records:push", token, "request_test_01", batch, http.StatusOK)
	if replayed["cursor"] != first["cursor"] {
		t.Fatal("idempotent response changed")
	}

	pulled := request(t, handler, "GET", "/v1/changes?after=0", token, "", nil, http.StatusOK)
	if len(pulled["changes"].([]any)) != 1 {
		t.Fatalf("unexpected changes: %#v", pulled)
	}
	request(t, handler, "POST", "/v1/records:push", token, "request_test_02", batch, http.StatusConflict)

	request(t, handler, "POST", "/v1/devices", session["token"].(string), "", map[string]any{
		"id": "device_test_02", "name": "Phone", "platform": "android",
	}, http.StatusCreated)
	devices := request(t, handler, "GET", "/v1/devices", token, "", nil, http.StatusOK)["devices"].([]any)
	if len(devices) != 2 {
		t.Fatalf("unexpected devices: %#v", devices)
	}
	request(t, handler, "DELETE", "/v1/devices/device_test_02", token, "", nil, http.StatusNoContent)
	devices = request(t, handler, "GET", "/v1/devices", token, "", nil, http.StatusOK)["devices"].([]any)
	if devices[0].(map[string]any)["revoked_at"] == nil && devices[1].(map[string]any)["revoked_at"] == nil {
		t.Fatal("revoked device is not marked")
	}
}

func TestQuotaEnforcement(t *testing.T) {
	opts := DefaultOptions()
	opts.MaxRecordsPerAccount = 2
	opts.MaxDevicesPerAccount = 1

	server, err := NewWithOptions(":memory:", opts)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	handler := server.Handler()

	accountID := "quota_account_01"
	authToken := strings.Repeat("b", 32)
	request(t, handler, "POST", "/v1/accounts", "", "", map[string]any{
		"account_id": accountID, "auth_token": authToken,
		"kdf":                  map[string]any{"algorithm": "argon2id", "memory_kib": 65536},
		"encrypted_key_bundle": blob(96), "nonce": blob(24),
	}, http.StatusCreated)

	session := request(t, handler, "POST", "/v1/sessions", "", "", map[string]any{
		"account_id": accountID, "auth_token": authToken,
	}, http.StatusCreated)
	token := session["token"].(string)

	// Device 1: Allowed
	request(t, handler, "POST", "/v1/devices", token, "", map[string]any{
		"id": "device_quota_01", "name": "Dev 1", "platform": "windows",
	}, http.StatusCreated)

	// Device 2: Exceeds MaxDevicesPerAccount (1)
	request(t, handler, "POST", "/v1/devices", token, "", map[string]any{
		"id": "device_quota_02", "name": "Dev 2", "platform": "android",
	}, http.StatusBadRequest)

	bound := request(t, handler, "POST", "/v1/sessions", "", "", map[string]any{
		"account_id": accountID, "auth_token": authToken, "device_id": "device_quota_01",
	}, http.StatusCreated)
	boundToken := bound["token"].(string)

	// Push 2 records (Allowed)
	batch := map[string]any{"protocol_version": 1, "records": []map[string]any{
		{
			"record_id": "rec_01", "kind": "post", "expected_revision": 0,
			"device_id": "device_quota_01", "ciphertext": blob(32), "nonce": blob(24), "tombstone": false,
		},
		{
			"record_id": "rec_02", "kind": "post", "expected_revision": 0,
			"device_id": "device_quota_01", "ciphertext": blob(32), "nonce": blob(24), "tombstone": false,
		},
	}}
	request(t, handler, "POST", "/v1/records:push", boundToken, "idem_0001", batch, http.StatusOK)

	// Push 3rd record: Exceeds MaxRecordsPerAccount (2)
	batch3 := map[string]any{"protocol_version": 1, "records": []map[string]any{
		{
			"record_id": "rec_03", "kind": "post", "expected_revision": 0,
			"device_id": "device_quota_01", "ciphertext": blob(32), "nonce": blob(24), "tombstone": false,
		},
	}}
	request(t, handler, "POST", "/v1/records:push", boundToken, "idem_0002", batch3, http.StatusRequestEntityTooLarge)
}

func TestRetentionPruning(t *testing.T) {
	server, err := New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	// Insert an expired session and an old idempotency key
	expiredTime := time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339)
	_, err = server.db.Exec(`INSERT INTO accounts(id,auth_token_hash,kdf_json,encrypted_key_bundle,nonce) VALUES('acc_ret','h','{}','b','n')`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = server.db.Exec(`INSERT INTO sessions(token_hash,account_id,expires_at) VALUES('t_exp','acc_ret',?)`, expiredTime)
	if err != nil {
		t.Fatal(err)
	}

	err = RunRetention(server.db, 30)
	if err != nil {
		t.Fatal(err)
	}

	var count int
	server.db.QueryRow(`SELECT COUNT(1) FROM sessions WHERE token_hash='t_exp'`).Scan(&count)
	if count != 0 {
		t.Fatalf("expected expired session to be pruned, got count=%d", count)
	}
}

func TestRejectsUnknownJSONFields(t *testing.T) {
	server, err := New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	request(t, server.Handler(), "POST", "/v1/accounts", "", "", map[string]any{"unexpected": true}, http.StatusBadRequest)
}

func request(t *testing.T, handler http.Handler, method, path, token, idempotency string, body any, status int) map[string]any {
	t.Helper()
	var encoded []byte
	if body != nil {
		encoded, _ = json.Marshal(body)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(encoded))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if idempotency != "" {
		req.Header.Set("Idempotency-Key", idempotency)
	}
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != status {
		t.Fatalf("%s %s: got %d, want %d: %s", method, path, res.Code, status, res.Body.String())
	}
	result := map[string]any{}
	if res.Body.Len() > 0 {
		_ = json.Unmarshal(res.Body.Bytes(), &result)
	}
	return result
}

func blob(size int) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, size))
}
