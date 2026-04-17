package codexlogin

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

func TestBuildActiveAuthJSONUsesCodexTokenShape(t *testing.T) {
	auth := &coreauth.Auth{
		ID:       "codex-test.json",
		Provider: "codex",
		Metadata: map[string]any{
			"access_token":  "access-1",
			"id_token":      "id-1",
			"refresh_token": "refresh-1",
			"account_id":    "account-1",
			"last_refresh":  "2026-04-17T01:02:03Z",
		},
	}

	data, err := BuildActiveAuthJSON(auth)
	if err != nil {
		t.Fatalf("BuildActiveAuthJSON returned error: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("generated JSON is invalid: %v", err)
	}

	if got["auth_mode"] != "chatgpt" {
		t.Fatalf("auth_mode = %#v, want chatgpt", got["auth_mode"])
	}
	if _, ok := got["OPENAI_API_KEY"]; !ok {
		t.Fatalf("OPENAI_API_KEY field is missing")
	}
	if got["OPENAI_API_KEY"] != nil {
		t.Fatalf("OPENAI_API_KEY = %#v, want null", got["OPENAI_API_KEY"])
	}
	if got["last_refresh"] != "2026-04-17T01:02:03Z" {
		t.Fatalf("last_refresh = %#v", got["last_refresh"])
	}
	tokens, ok := got["tokens"].(map[string]any)
	if !ok {
		t.Fatalf("tokens = %T, want object", got["tokens"])
	}
	if tokens["access_token"] != "access-1" {
		t.Fatalf("access_token = %#v", tokens["access_token"])
	}
	if tokens["id_token"] != "id-1" {
		t.Fatalf("id_token = %#v", tokens["id_token"])
	}
	if tokens["refresh_token"] != "refresh-1" {
		t.Fatalf("refresh_token = %#v", tokens["refresh_token"])
	}
	if tokens["account_id"] != "account-1" {
		t.Fatalf("account_id = %#v", tokens["account_id"])
	}
}

func TestBuildActiveAuthJSONRejectsMissingRequiredTokens(t *testing.T) {
	auth := &coreauth.Auth{
		ID:       "codex-test.json",
		Provider: "codex",
		Metadata: map[string]any{
			"access_token": "access-1",
		},
	}

	if _, err := BuildActiveAuthJSON(auth); err == nil {
		t.Fatalf("expected error for missing token fields")
	}
}

func TestWriteActiveAuthFileWritesAtomically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".codex", "auth.json")
	auth := &coreauth.Auth{
		ID:       "codex-test.json",
		Provider: "codex",
		Metadata: map[string]any{
			"access_token":  "access-1",
			"id_token":      "id-1",
			"refresh_token": "refresh-1",
			"account_id":    "account-1",
		},
	}

	if err := WriteActiveAuthFile(path, auth); err != nil {
		t.Fatalf("WriteActiveAuthFile returned error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read written auth file: %v", err)
	}
	if !json.Valid(data) {
		t.Fatalf("written auth file is not valid JSON: %s", data)
	}
}
