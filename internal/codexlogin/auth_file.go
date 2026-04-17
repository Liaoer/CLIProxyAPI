package codexlogin

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

type activeCodexAuth struct {
	OpenAIAPIKey *string           `json:"OPENAI_API_KEY"`
	AuthMode     string            `json:"auth_mode"`
	LastRefresh  string            `json:"last_refresh,omitempty"`
	Tokens       activeCodexTokens `json:"tokens"`
}

type activeCodexTokens struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	AccountID    string `json:"account_id,omitempty"`
}

// DefaultActiveAuthPath resolves the Codex CLI/App auth file for the current OS user.
func DefaultActiveAuthPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(home) == "" {
		return "", fmt.Errorf("user home directory is empty")
	}
	return filepath.Join(home, ".codex", "auth.json"), nil
}

// BuildActiveAuthJSON converts a CLIProxyAPI Codex auth record into Codex's active auth.json shape.
func BuildActiveAuthJSON(auth *coreauth.Auth) ([]byte, error) {
	if auth == nil {
		return nil, fmt.Errorf("codex auth is required")
	}
	if !strings.EqualFold(strings.TrimSpace(auth.Provider), "codex") {
		return nil, fmt.Errorf("auth %s is not a codex auth", auth.ID)
	}
	meta := auth.Metadata
	if meta == nil {
		return nil, fmt.Errorf("codex auth metadata is empty")
	}
	accessToken := metadataString(meta, "access_token")
	idToken := metadataString(meta, "id_token")
	refreshToken := metadataString(meta, "refresh_token")
	if accessToken == "" || idToken == "" || refreshToken == "" {
		return nil, fmt.Errorf("codex auth is missing required token fields")
	}
	lastRefresh := metadataString(meta, "last_refresh")
	if lastRefresh == "" {
		lastRefresh = time.Now().UTC().Format(time.RFC3339)
	}
	payload := activeCodexAuth{
		OpenAIAPIKey: nil,
		AuthMode:     "chatgpt",
		LastRefresh:  lastRefresh,
		Tokens: activeCodexTokens{
			AccessToken:  accessToken,
			IDToken:      idToken,
			RefreshToken: refreshToken,
			AccountID:    metadataString(meta, "account_id"),
		},
	}
	return json.MarshalIndent(payload, "", "  ")
}

// WriteActiveAuthFile atomically writes the supplied Codex auth as the active Codex login.
func WriteActiveAuthFile(path string, auth *coreauth.Auth) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("active codex auth path is required")
	}
	data, err := BuildActiveAuthJSON(auth)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create codex auth directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "auth-*.json")
	if err != nil {
		return fmt.Errorf("failed to create temporary codex auth file: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to write temporary codex auth file: %w", err)
	}
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to set codex auth file permissions: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close temporary codex auth file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		if removeErr := os.Remove(path); removeErr != nil && !os.IsNotExist(removeErr) {
			return fmt.Errorf("failed to replace existing codex auth file: %w", removeErr)
		}
		if renameErr := os.Rename(tmpPath, path); renameErr != nil {
			return fmt.Errorf("failed to activate codex auth file: %w", renameErr)
		}
	}
	cleanup = false
	return nil
}

func metadataString(meta map[string]any, key string) string {
	if meta == nil {
		return ""
	}
	switch value := meta[key].(type) {
	case string:
		return strings.TrimSpace(value)
	case nil:
		return ""
	default:
		return strings.TrimSpace(fmt.Sprint(value))
	}
}
