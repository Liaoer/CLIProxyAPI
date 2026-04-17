package management

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

func TestHealthReportReturnsFocusedCodexDiagnostics(t *testing.T) {
	manager := coreauth.NewManager(&memoryAuthStore{}, nil, nil)
	_, err := manager.Register(context.Background(), &coreauth.Auth{
		ID:       "codex-managed",
		FileName: "codex-managed.json",
		Provider: "codex",
		Metadata: map[string]any{
			"email":         "managed@example.com",
			"account_id":    "managed-account",
			"access_token":  "managed-access",
			"id_token":      "managed-id",
			"refresh_token": "managed-refresh",
		},
	})
	if err != nil {
		t.Fatalf("register auth: %v", err)
	}

	gin.SetMode(gin.TestMode)
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, manager)
	h.codexActiveAuthPath = func() (string, error) {
		return filepath.Join(t.TempDir(), "missing-auth.json"), nil
	}

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/health-report?auth_id=codex-managed", nil)
	h.HealthReport(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	bodyText := rec.Body.String()
	var body struct {
		Overall  string `json:"overall"`
		Accounts []struct {
			ID         string   `json:"id"`
			ReasonCode []string `json:"reason_codes"`
		} `json:"accounts"`
		Checks []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"checks"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Overall != "warning" {
		t.Fatalf("overall = %q, want warning; body=%s", body.Overall, bodyText)
	}
	if len(body.Accounts) != 1 || body.Accounts[0].ID != "codex-managed" {
		t.Fatalf("accounts = %#v, want focused codex-managed", body.Accounts)
	}
	if !strings.Contains(bodyText, "ACTIVE_CODEX_AUTH_FILE_MISSING") {
		t.Fatalf("expected missing active auth reason, body=%s", bodyText)
	}
}

func TestHealthReportDeepQueryRunsLiveRefresh(t *testing.T) {
	manager := coreauth.NewManager(&memoryAuthStore{}, nil, nil)
	manager.RegisterExecutor(codexSwitchRefreshExecutor{})
	_, err := manager.Register(context.Background(), &coreauth.Auth{
		ID:       "codex-live",
		FileName: "codex-live.json",
		Provider: "codex",
		Metadata: map[string]any{
			"email":         "live@example.com",
			"account_id":    "live-account",
			"access_token":  "live-access",
			"id_token":      "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.c2ln",
			"refresh_token": "live-refresh",
		},
	})
	if err != nil {
		t.Fatalf("register auth: %v", err)
	}

	gin.SetMode(gin.TestMode)
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, manager)

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/health-report?deep=true", nil)
	h.HealthReport(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var body struct {
		Mode           string `json:"mode"`
		Summary        string `json:"summary"`
		Headline       string `json:"headline"`
		OperatorAdvice string `json:"operator_advice"`
		Accounts       []struct {
			ID          string `json:"id"`
			LiveStatus  string `json:"live_status"`
			LiveSummary string `json:"live_summary"`
		} `json:"accounts"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Mode != "deep" {
		t.Fatalf("mode = %q, want deep", body.Mode)
	}
	if !strings.Contains(body.Summary, "在线体检") {
		t.Fatalf("summary = %q, want online health summary", body.Summary)
	}
	if !strings.Contains(body.Headline, "在线体检通过") {
		t.Fatalf("headline = %q, want online healthy headline", body.Headline)
	}
	if !strings.Contains(body.OperatorAdvice, "无需额外处理") {
		t.Fatalf("operator advice = %q, want healthy operator guidance", body.OperatorAdvice)
	}
	if len(body.Accounts) != 1 || body.Accounts[0].LiveStatus != "pass" {
		t.Fatalf("accounts = %#v, want single live pass account", body.Accounts)
	}
	if !strings.Contains(body.Accounts[0].LiveSummary, "在线刷新通过") {
		t.Fatalf("live summary = %q, want live refresh pass", body.Accounts[0].LiveSummary)
	}
}
