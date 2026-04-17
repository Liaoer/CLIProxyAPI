package management

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

func TestListAuthFiles_FiltersStopSyncForNonWebUI(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	gin.SetMode(gin.TestMode)

	authDir := t.TempDir()
	fileName := "codex-sync-hidden.json"
	filePath := filepath.Join(authDir, fileName)
	if errWrite := os.WriteFile(filePath, []byte(`{"type":"codex","email":"hidden@example.com","stop_sync":true}`), 0o600); errWrite != nil {
		t.Fatalf("failed to write auth file: %v", errWrite)
	}

	manager := coreauth.NewManager(nil, nil, nil)
	record := &coreauth.Auth{
		ID:       fileName,
		FileName: fileName,
		Provider: "codex",
		Attributes: map[string]string{
			"path":      filePath,
			"stop_sync": "true",
		},
		Metadata: map[string]any{
			"type":      "codex",
			"email":     "hidden@example.com",
			"stop_sync": true,
		},
	}
	if _, errRegister := manager.Register(context.Background(), record); errRegister != nil {
		t.Fatalf("failed to register auth record: %v", errRegister)
	}

	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodGet, "/v0/management/auth-files", nil)
	ctx.Request = req
	h.ListAuthFiles(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d with body %s", http.StatusOK, rec.Code, rec.Body.String())
	}

	files := decodeAuthFilesList(t, rec.Body.Bytes())
	if len(files) != 0 {
		t.Fatalf("expected stop-sync auth to be hidden from non-webui list, got %d entries", len(files))
	}
}

func TestListAuthFiles_KeepStopSyncForWebUI(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	gin.SetMode(gin.TestMode)

	authDir := t.TempDir()
	fileName := "codex-sync-visible.json"
	filePath := filepath.Join(authDir, fileName)
	if errWrite := os.WriteFile(filePath, []byte(`{"type":"codex","email":"visible@example.com","stop_sync":true}`), 0o600); errWrite != nil {
		t.Fatalf("failed to write auth file: %v", errWrite)
	}

	manager := coreauth.NewManager(nil, nil, nil)
	record := &coreauth.Auth{
		ID:       fileName,
		FileName: fileName,
		Provider: "codex",
		Attributes: map[string]string{
			"path":      filePath,
			"stop_sync": "true",
		},
		Metadata: map[string]any{
			"type":      "codex",
			"email":     "visible@example.com",
			"stop_sync": true,
		},
	}
	if _, errRegister := manager.Register(context.Background(), record); errRegister != nil {
		t.Fatalf("failed to register auth record: %v", errRegister)
	}

	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodGet, "/v0/management/auth-files?is_webui=1", nil)
	ctx.Request = req
	h.ListAuthFiles(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d with body %s", http.StatusOK, rec.Code, rec.Body.String())
	}

	files := decodeAuthFilesList(t, rec.Body.Bytes())
	if len(files) != 1 {
		t.Fatalf("expected stop-sync auth to remain visible for webui list, got %d entries", len(files))
	}
	if got := files[0]["stop_sync"]; got != true {
		t.Fatalf("expected stop_sync = true in response, got %#v", got)
	}
}

func decodeAuthFilesList(t *testing.T, body []byte) []map[string]any {
	t.Helper()

	var payload struct {
		Files []map[string]any `json:"files"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("failed to decode list payload: %v", err)
	}
	return payload.Files
}
