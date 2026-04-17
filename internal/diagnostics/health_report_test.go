package diagnostics

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
)

type memoryStore struct {
	items map[string]*coreauth.Auth
}

func (s *memoryStore) List(context.Context) ([]*coreauth.Auth, error) {
	out := make([]*coreauth.Auth, 0, len(s.items))
	for _, item := range s.items {
		out = append(out, item)
	}
	return out, nil
}

func (s *memoryStore) Save(_ context.Context, auth *coreauth.Auth) (string, error) {
	if s.items == nil {
		s.items = map[string]*coreauth.Auth{}
	}
	s.items[auth.ID] = auth
	return auth.ID, nil
}

func (s *memoryStore) Delete(_ context.Context, id string) error {
	delete(s.items, id)
	return nil
}

type diagnosticsRefreshExecutor struct {
	err       error
	errs      map[string]error
	refreshed int
}

func (e *diagnosticsRefreshExecutor) Identifier() string { return "codex" }
func (e *diagnosticsRefreshExecutor) Execute(context.Context, *coreauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}
func (e *diagnosticsRefreshExecutor) ExecuteStream(context.Context, *coreauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	return nil, nil
}
func (e *diagnosticsRefreshExecutor) Refresh(_ context.Context, auth *coreauth.Auth) (*coreauth.Auth, error) {
	e.refreshed++
	if e.errs != nil {
		if authErr, ok := e.errs[auth.ID]; ok && authErr != nil {
			return nil, authErr
		}
	}
	if e.err != nil {
		return nil, e.err
	}
	if auth.Metadata == nil {
		auth.Metadata = map[string]any{}
	}
	auth.Metadata["refresh_token"] = "refreshed-token"
	auth.Metadata["last_refresh"] = "2026-04-17T02:03:04Z"
	return auth, nil
}
func (e *diagnosticsRefreshExecutor) CountTokens(context.Context, *coreauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}
func (e *diagnosticsRefreshExecutor) HttpRequest(context.Context, *coreauth.Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}

func TestGenerateHealthReportClassifiesCodexAuthProblems(t *testing.T) {
	manager := coreauth.NewManager(&memoryStore{}, nil, nil)
	_, err := manager.Register(context.Background(), &coreauth.Auth{
		ID:       "codex-broken",
		Provider: "codex",
		Label:    "Broken Codex",
		Metadata: map[string]any{
			"email":        "broken@example.com",
			"access_token": "access-token",
			"id_token":     "not-a-jwt",
		},
		LastError: &coreauth.Error{
			Message:    "Authorization expired. Please sign in again.",
			HTTPStatus: 401,
		},
	})
	if err != nil {
		t.Fatalf("register auth: %v", err)
	}

	report, err := Generate(context.Background(), Options{
		AuthManager: manager,
		Now:         time.Date(2026, 4, 17, 8, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	if report.Overall != OverallCritical {
		t.Fatalf("overall = %q, want %q", report.Overall, OverallCritical)
	}
	account := findAccount(report, "codex-broken")
	if account == nil {
		t.Fatalf("account health not found: %#v", report.Accounts)
	}
	assertReason(t, account.ReasonCodes, ReasonRefreshTokenMissing)
	assertReason(t, account.ReasonCodes, ReasonIDTokenParseFailed)
	assertReason(t, account.ReasonCodes, ReasonAuthExpired)
	assertCheck(t, report.Checks, "codex.refresh_token_present", CheckFail)
}

func TestGenerateHealthReportDetectsActiveCodexMismatch(t *testing.T) {
	manager := coreauth.NewManager(&memoryStore{}, nil, nil)
	_, err := manager.Register(context.Background(), &coreauth.Auth{
		ID:       "codex-managed",
		Provider: "codex",
		Label:    "Managed Codex",
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
	authPath := filepath.Join(t.TempDir(), "auth.json")
	if err := os.WriteFile(authPath, []byte(`{
  "auth_mode": "chatgpt",
  "tokens": {
    "account_id": "other-account",
    "access_token": "other-access",
    "id_token": "other-id",
    "refresh_token": "other-refresh"
  }
}`), 0o600); err != nil {
		t.Fatalf("write active auth: %v", err)
	}

	report, err := Generate(context.Background(), Options{
		AuthManager: manager,
		AuthID:      "codex-managed",
		ActiveCodexAuthPath: func() (string, error) {
			return authPath, nil
		},
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	if report.Overall != OverallWarning {
		t.Fatalf("overall = %q, want %q", report.Overall, OverallWarning)
	}
	account := findAccount(report, "codex-managed")
	if account == nil {
		t.Fatalf("account health not found: %#v", report.Accounts)
	}
	assertReason(t, account.ReasonCodes, ReasonActiveCodexMismatch)
	assertCheck(t, report.Checks, "codex.active_auth_matches_managed_account", CheckWarn)
	if len(report.RecommendedActions) == 0 || report.RecommendedActions[0].Action != "switch_codex" {
		t.Fatalf("recommended actions = %#v, want switch_codex", report.RecommendedActions)
	}
}

func TestGenerateHealthReportDeepRefreshMarksLiveCheckPassed(t *testing.T) {
	manager := coreauth.NewManager(&memoryStore{}, nil, nil)
	executor := &diagnosticsRefreshExecutor{}
	manager.RegisterExecutor(executor)
	_, err := manager.Register(context.Background(), &coreauth.Auth{
		ID:       "codex-live-ok",
		Provider: "codex",
		Label:    "Live Codex",
		Metadata: map[string]any{
			"email":         "live@example.com",
			"account_id":    "live-account",
			"access_token":  "access-token",
			"id_token":      "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.c2ln",
			"refresh_token": "refresh-token",
		},
	})
	if err != nil {
		t.Fatalf("register auth: %v", err)
	}

	report, err := Generate(context.Background(), Options{
		AuthManager: manager,
		Now:         time.Date(2026, 4, 17, 9, 0, 0, 0, time.UTC),
		Deep:        true,
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	if executor.refreshed != 1 {
		t.Fatalf("refresh count = %d, want 1", executor.refreshed)
	}
	if report.Overall != OverallHealthy {
		t.Fatalf("overall = %q, want %q", report.Overall, OverallHealthy)
	}
	assertCheck(t, report.Checks, "codex.live_refresh", CheckPass)
	account := findAccount(report, "codex-live-ok")
	if account == nil {
		t.Fatalf("account health not found: %#v", report.Accounts)
	}
	if account.LiveStatus != CheckPass {
		t.Fatalf("live status = %q, want %q", account.LiveStatus, CheckPass)
	}
	if account.LiveSummary == "" {
		t.Fatalf("expected live summary to be populated")
	}
}

func TestGenerateHealthReportDeepRefreshMarksExpiredAuthCritical(t *testing.T) {
	manager := coreauth.NewManager(&memoryStore{}, nil, nil)
	executor := &diagnosticsRefreshExecutor{err: errors.New("Authorization expired. Please sign in again.")}
	manager.RegisterExecutor(executor)
	_, err := manager.Register(context.Background(), &coreauth.Auth{
		ID:       "codex-live-expired",
		Provider: "codex",
		Label:    "Expired Codex",
		Metadata: map[string]any{
			"email":         "expired@example.com",
			"account_id":    "expired-account",
			"access_token":  "access-token",
			"id_token":      "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.c2ln",
			"refresh_token": "refresh-token",
		},
	})
	if err != nil {
		t.Fatalf("register auth: %v", err)
	}

	report, err := Generate(context.Background(), Options{
		AuthManager: manager,
		Now:         time.Date(2026, 4, 17, 9, 5, 0, 0, time.UTC),
		Deep:        true,
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	if executor.refreshed != 1 {
		t.Fatalf("refresh count = %d, want 1", executor.refreshed)
	}
	if report.Overall != OverallCritical {
		t.Fatalf("overall = %q, want %q", report.Overall, OverallCritical)
	}
	assertCheck(t, report.Checks, "codex.live_refresh", CheckFail)
	account := findAccount(report, "codex-live-expired")
	if account == nil {
		t.Fatalf("account health not found: %#v", report.Accounts)
	}
	assertReason(t, account.ReasonCodes, ReasonAuthExpired)
	if account.LiveStatus != CheckFail {
		t.Fatalf("live status = %q, want %q", account.LiveStatus, CheckFail)
	}
	if account.LiveSummary == "" {
		t.Fatalf("expected live summary to be populated")
	}
}

func TestGenerateHealthReportDeepRefreshHumanizesReusedRefreshToken(t *testing.T) {
	manager := coreauth.NewManager(&memoryStore{}, nil, nil)
	executor := &diagnosticsRefreshExecutor{
		err: errors.New(`token refresh failed with status 401: {"error":{"message":"Session refresh blocked.","type":"invalid_request_error","param":null,"code":"refresh_token_reused"}}`),
	}
	manager.RegisterExecutor(executor)
	_, err := manager.Register(context.Background(), &coreauth.Auth{
		ID:       "codex-live-reused",
		Provider: "codex",
		Label:    "Reused Codex",
		Metadata: map[string]any{
			"email":         "reused@example.com",
			"account_id":    "reused-account",
			"access_token":  "access-token",
			"id_token":      "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.c2ln",
			"refresh_token": "refresh-token",
		},
	})
	if err != nil {
		t.Fatalf("register auth: %v", err)
	}

	report, err := Generate(context.Background(), Options{
		AuthManager: manager,
		Now:         time.Date(2026, 4, 17, 9, 10, 0, 0, time.UTC),
		Deep:        true,
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	account := findAccount(report, "codex-live-reused")
	if account == nil {
		t.Fatalf("account health not found: %#v", report.Accounts)
	}
	if report.Headline == "" || !strings.Contains(report.Headline, "refresh token") || !strings.Contains(report.Headline, "鍏朵粬瀹㈡埛绔?) {
		t.Fatalf("headline = %q, want reused token guidance", report.Headline)
	}
	if !strings.Contains(report.OperatorAdvice, "閲嶆柊鍚屾鎴栭噸鏂板鍏?) {
		t.Fatalf("operator advice = %q, want recovery steps", report.OperatorAdvice)
	}
	if account.PrimaryReasonCode != ReasonRefreshTokenReused {
		t.Fatalf("primary reason = %q, want %q", account.PrimaryReasonCode, ReasonRefreshTokenReused)
	}
	if !strings.Contains(account.DisplayMessage, "鏃?token") {
		t.Fatalf("display message = %q, want reused-token explanation", account.DisplayMessage)
	}
	if !strings.Contains(account.NextStep, "閲嶆柊鍚屾") {
		t.Fatalf("next step = %q, want resync guidance", account.NextStep)
	}
}

func TestGenerateHealthReportUsesGenericHeadlineForMixedReasons(t *testing.T) {
	manager := coreauth.NewManager(&memoryStore{}, nil, nil)
	executor := &diagnosticsRefreshExecutor{
		errs: map[string]error{
			"codex-reused":  errors.New(`token refresh failed with status 401: {"error":{"message":"Session refresh blocked.","type":"invalid_request_error","param":null,"code":"refresh_token_reused"}}`),
			"codex-expired": errors.New("Authorization expired. Please sign in again."),
		},
	}
	manager.RegisterExecutor(executor)

	for _, auth := range []*coreauth.Auth{
		{
			ID:       "codex-reused",
			Provider: "codex",
			Label:    "Reused Codex",
			Metadata: map[string]any{
				"email":         "reused@example.com",
				"account_id":    "reused-account",
				"access_token":  "access-token",
				"id_token":      "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.c2ln",
				"refresh_token": "refresh-token-a",
			},
		},
		{
			ID:       "codex-expired",
			Provider: "codex",
			Label:    "Expired Codex",
			Metadata: map[string]any{
				"email":         "expired@example.com",
				"account_id":    "expired-account",
				"access_token":  "access-token",
				"id_token":      "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.c2ln",
				"refresh_token": "refresh-token-b",
			},
		},
	} {
		if _, err := manager.Register(context.Background(), auth); err != nil {
			t.Fatalf("register auth %s: %v", auth.ID, err)
		}
	}

	report, err := Generate(context.Background(), Options{
		AuthManager: manager,
		Now:         time.Date(2026, 4, 17, 9, 15, 0, 0, time.UTC),
		Deep:        true,
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	if !strings.Contains(report.Headline, "澶氫釜涓嶅悓鍘熷洜") {
		t.Fatalf("headline = %q, want generic mixed-reason guidance", report.Headline)
	}
	reused := findAccount(report, "codex-reused")
	expired := findAccount(report, "codex-expired")
	if reused == nil || expired == nil {
		t.Fatalf("accounts missing: %#v", report.Accounts)
	}
	if reused.PrimaryReasonCode != ReasonRefreshTokenReused {
		t.Fatalf("reused primary reason = %q, want %q", reused.PrimaryReasonCode, ReasonRefreshTokenReused)
	}
	if expired.PrimaryReasonCode != ReasonAuthExpired {
		t.Fatalf("expired primary reason = %q, want %q", expired.PrimaryReasonCode, ReasonAuthExpired)
	}
}

func TestGenerateHealthReportHumanizesActiveCodexMismatch(t *testing.T) {
	manager := coreauth.NewManager(&memoryStore{}, nil, nil)
	_, err := manager.Register(context.Background(), &coreauth.Auth{
		ID:       "codex-managed",
		Provider: "codex",
		Label:    "Managed Codex",
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
	authPath := filepath.Join(t.TempDir(), "auth.json")
	if err := os.WriteFile(authPath, []byte(`{
  "auth_mode": "chatgpt",
  "tokens": {
    "account_id": "other-account",
    "access_token": "other-access",
    "id_token": "other-id",
    "refresh_token": "other-refresh"
  }
}`), 0o600); err != nil {
		t.Fatalf("write active auth: %v", err)
	}

	report, err := Generate(context.Background(), Options{
		AuthManager: manager,
		AuthID:      "codex-managed",
		ActiveCodexAuthPath: func() (string, error) {
			return authPath, nil
		},
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	account := findAccount(report, "codex-managed")
	if account == nil {
		t.Fatalf("account health not found: %#v", report.Accounts)
	}
	if account.PrimaryReasonCode != ReasonActiveCodexMismatch {
		t.Fatalf("primary reason = %q, want %q", account.PrimaryReasonCode, ReasonActiveCodexMismatch)
	}
	if !strings.Contains(account.DisplayTitle, "Codex") {
		t.Fatalf("display title = %q, want Codex mismatch title", account.DisplayTitle)
	}
	if !strings.Contains(account.NextStep, "鍒囨崲鍒?Codex") {
		t.Fatalf("next step = %q, want switch guidance", account.NextStep)
	}
	if strings.Contains(account.NextStep, "閲嶆柊鎺堟潈") {
		t.Fatalf("next step = %q, should not ask for reauthorize", account.NextStep)
	}
}

func TestGenerateHealthReportSkipsMissingDisabledHiddenAuths(t *testing.T) {
	manager := coreauth.NewManager(&memoryStore{}, nil, nil)
	tempDir := t.TempDir()
	visiblePath := filepath.Join(tempDir, "codex-visible.json")
	if err := os.WriteFile(visiblePath, []byte(`{"type":"codex"}`), 0o600); err != nil {
		t.Fatalf("write visible auth: %v", err)
	}
	for _, auth := range []*coreauth.Auth{
		{
			ID:       "codex-hidden-free.json",
			FileName: "codex-hidden-free.json",
			Provider: "codex",
			Status:   coreauth.StatusDisabled,
			Disabled: true,
			Attributes: map[string]string{
				"path": filepath.Join(tempDir, "missing-free.json"),
			},
			Metadata: map[string]any{
				"email":         "ekeltay945@gmail.com",
				"account_id":    "d07ac69d-69da-4d9c-a44c-1c1b703afbab",
				"refresh_token": "old-refresh-token",
			},
		},
		{
			ID:       "codex-ekeltay945@gmail.com-plus.json",
			FileName: "codex-ekeltay945@gmail.com-plus.json",
			Provider: "codex",
			Status:   coreauth.StatusActive,
			Attributes: map[string]string{
				"path": visiblePath,
			},
			Metadata: map[string]any{
				"email":         "ekeltay945@gmail.com",
				"account_id":    "d07ac69d-69da-4d9c-a44c-1c1b703afbab",
				"refresh_token": "fresh-refresh-token",
				"id_token":      "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.c2ln",
			},
		},
	} {
		if _, err := manager.Register(context.Background(), auth); err != nil {
			t.Fatalf("register auth %s: %v", auth.ID, err)
		}
	}
	report, err := Generate(context.Background(), Options{AuthManager: manager})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	if len(report.Accounts) != 1 {
		t.Fatalf("accounts = %#v, want only visible auth", report.Accounts)
	}
	if report.Accounts[0].ID != "codex-ekeltay945@gmail.com-plus.json" {
		t.Fatalf("account id = %q, want visible plus auth", report.Accounts[0].ID)
	}
}
func findAccount(report *Report, id string) *AccountHealth {
	if report == nil {
		return nil
	}
	for i := range report.Accounts {
		if report.Accounts[i].ID == id {
			return &report.Accounts[i]
		}
	}
	return nil
}

func assertReason(t *testing.T, reasons []ReasonCode, want ReasonCode) {
	t.Helper()
	for _, reason := range reasons {
		if reason == want {
			return
		}
	}
	t.Fatalf("reason %q not found in %#v", want, reasons)
}

func assertCheck(t *testing.T, checks []Check, id string, want CheckStatus) {
	t.Helper()
	for _, check := range checks {
		if check.ID == id {
			if check.Status != want {
				t.Fatalf("check %s status = %q, want %q", id, check.Status, want)
			}
			return
		}
	}
	t.Fatalf("check %s not found in %#v", id, checks)
}



