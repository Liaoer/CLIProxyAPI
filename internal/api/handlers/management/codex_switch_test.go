package management

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
)

type codexSwitchRefreshExecutor struct {
	err error
}

func (e codexSwitchRefreshExecutor) Identifier() string { return "codex" }
func (e codexSwitchRefreshExecutor) Execute(context.Context, *coreauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}
func (e codexSwitchRefreshExecutor) ExecuteStream(context.Context, *coreauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	return nil, nil
}
func (e codexSwitchRefreshExecutor) Refresh(_ context.Context, auth *coreauth.Auth) (*coreauth.Auth, error) {
	if e.err != nil {
		return nil, e.err
	}
	if auth.Metadata == nil {
		auth.Metadata = map[string]any{}
	}
	auth.Metadata["access_token"] = "new-access"
	auth.Metadata["id_token"] = "new-id"
	auth.Metadata["refresh_token"] = "new-refresh"
	auth.Metadata["account_id"] = "account-1"
	auth.Metadata["last_refresh"] = "2026-04-17T01:02:03Z"
	auth.Metadata["type"] = "codex"
	return auth, nil
}
func (e codexSwitchRefreshExecutor) CountTokens(context.Context, *coreauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}
func (e codexSwitchRefreshExecutor) HttpRequest(context.Context, *coreauth.Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}

func TestSwitchCodexAuthRefreshesAndWritesActiveAuth(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	gin.SetMode(gin.TestMode)

	store := &memoryAuthStore{}
	manager := coreauth.NewManager(store, nil, nil)
	manager.RegisterExecutor(codexSwitchRefreshExecutor{})
	record := &coreauth.Auth{
		ID:       "codex-test.json",
		FileName: "codex-test.json",
		Provider: "codex",
		Metadata: map[string]any{
			"access_token":  "old-access",
			"id_token":      "old-id",
			"refresh_token": "old-refresh",
			"account_id":    "account-1",
			"type":          "codex",
		},
	}
	if _, err := manager.Register(context.Background(), record); err != nil {
		t.Fatalf("failed to register auth: %v", err)
	}

	authPath := filepath.Join(t.TempDir(), ".codex", "auth.json")
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, manager)
	h.codexActiveAuthPath = func() (string, error) { return authPath, nil }

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodPost, "/v0/management/codex/switch-auth", strings.NewReader(`{"name":"codex-test.json"}`))
	req.Header.Set("Content-Type", "application/json")
	ctx.Request = req

	h.SwitchCodexAuth(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d with body %s", http.StatusOK, rec.Code, rec.Body.String())
	}

	data, err := os.ReadFile(authPath)
	if err != nil {
		t.Fatalf("failed to read active auth file: %v", err)
	}
	if got := string(data); !strings.Contains(got, "new-access") || strings.Contains(got, "old-access") {
		t.Fatalf("active auth file was not written with refreshed tokens: %s", got)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	if body["refreshed"] != true {
		t.Fatalf("response refreshed = %#v, want true", body["refreshed"])
	}
}

func TestSwitchCodexAuthRefreshFailureDoesNotOverwriteActiveAuth(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	gin.SetMode(gin.TestMode)

	store := &memoryAuthStore{}
	manager := coreauth.NewManager(store, nil, nil)
	manager.RegisterExecutor(codexSwitchRefreshExecutor{err: errors.New("refresh_token_reused")})
	record := &coreauth.Auth{
		ID:       "codex-test.json",
		FileName: "codex-test.json",
		Provider: "codex",
		Metadata: map[string]any{
			"access_token":  "old-access",
			"id_token":      "old-id",
			"refresh_token": "old-refresh",
			"account_id":    "account-1",
			"type":          "codex",
		},
	}
	if _, err := manager.Register(context.Background(), record); err != nil {
		t.Fatalf("failed to register auth: %v", err)
	}

	authPath := filepath.Join(t.TempDir(), ".codex", "auth.json")
	if err := os.MkdirAll(filepath.Dir(authPath), 0700); err != nil {
		t.Fatalf("failed to create active auth dir: %v", err)
	}
	if err := os.WriteFile(authPath, []byte(`{"sentinel":"keep"}`), 0600); err != nil {
		t.Fatalf("failed to write sentinel auth file: %v", err)
	}

	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, manager)
	h.codexActiveAuthPath = func() (string, error) { return authPath, nil }

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodPost, "/v0/management/codex/switch-auth", strings.NewReader(`{"name":"codex-test.json"}`))
	req.Header.Set("Content-Type", "application/json")
	ctx.Request = req

	h.SwitchCodexAuth(ctx)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d with body %s", http.StatusUnauthorized, rec.Code, rec.Body.String())
	}
	data, err := os.ReadFile(authPath)
	if err != nil {
		t.Fatalf("failed to read active auth file: %v", err)
	}
	if string(data) != `{"sentinel":"keep"}` {
		t.Fatalf("active auth file was overwritten on refresh failure: %s", data)
	}
	if !strings.Contains(rec.Body.String(), `"reauth_required":true`) {
		t.Fatalf("response should mark reauth_required: %s", rec.Body.String())
	}
}
