package management

import (
	"errors"
	"net/http"
	"os/exec"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/codexlogin"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

type codexSwitchRequest struct {
	AuthID      string `json:"auth_id"`
	Name        string `json:"name"`
	Refresh     *bool  `json:"refresh"`
	LaunchCodex bool   `json:"launch_codex"`
}

// SwitchCodexAuth switches the current user's Codex CLI/App login to a managed Codex auth.
func (h *Handler) SwitchCodexAuth(c *gin.Context) {
	if h == nil || h.authManager == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"ok": false, "error": "handler not initialized"})
		return
	}

	var req codexSwitchRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "invalid JSON body"})
		return
	}
	auth, ok := h.findCodexSwitchAuth(req.AuthID, req.Name)
	if !ok || auth == nil {
		c.JSON(http.StatusNotFound, gin.H{"ok": false, "error": "auth not found"})
		return
	}
	if !strings.EqualFold(strings.TrimSpace(auth.Provider), "codex") {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "selected auth is not a Codex auth"})
		return
	}
	if auth.Disabled || auth.Status == coreauth.StatusDisabled {
		c.JSON(http.StatusConflict, gin.H{"ok": false, "error": "selected auth is disabled"})
		return
	}

	shouldRefresh := true
	if req.Refresh != nil {
		shouldRefresh = *req.Refresh
	}
	refreshed := false
	if shouldRefresh {
		updated, err := h.authManager.RefreshByID(c.Request.Context(), auth.ID)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"ok":              false,
				"error":           "Codex auth refresh failed. Please re-authorize this account.",
				"detail":          err.Error(),
				"reauth_required": isCodexSwitchReauthError(err),
			})
			return
		}
		auth = updated
		refreshed = true
	}

	resolvePath := h.codexActiveAuthPath
	if resolvePath == nil {
		resolvePath = codexlogin.DefaultActiveAuthPath
	}
	authPath, err := resolvePath()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"ok": false, "error": "failed to resolve Codex auth path", "detail": err.Error()})
		return
	}
	if err := codexlogin.WriteActiveAuthFile(authPath, auth); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"ok": false, "error": "failed to write Codex active auth", "detail": err.Error()})
		return
	}

	launched := false
	launchError := ""
	if req.LaunchCodex {
		if err := exec.Command("codex", "app").Start(); err != nil {
			launchError = err.Error()
		} else {
			launched = true
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"ok":              true,
		"auth_id":         auth.ID,
		"email":           authEmail(auth),
		"account_id":      codexSwitchMetadataString(auth, "account_id"),
		"refreshed":       refreshed,
		"codex_auth_path": authPath,
		"launched":        launched,
		"launch_error":    launchError,
		"reauth_required": false,
	})
}

func (h *Handler) findCodexSwitchAuth(authID, name string) (*coreauth.Auth, bool) {
	authID = strings.TrimSpace(authID)
	name = strings.TrimSpace(name)
	if authID != "" {
		return h.authManager.GetByID(authID)
	}
	if name == "" {
		return nil, false
	}
	if auth, ok := h.authManager.GetByID(name); ok {
		return auth, true
	}
	for _, auth := range h.authManager.List() {
		if auth == nil {
			continue
		}
		if auth.FileName == name || auth.ID == name {
			return auth, true
		}
	}
	return nil, false
}

func isCodexSwitchReauthError(err error) bool {
	if err == nil {
		return false
	}
	var authErr *coreauth.Error
	if errors.As(err, &authErr) {
		if authErr.HTTPStatus == http.StatusUnauthorized || authErr.HTTPStatus == http.StatusForbidden {
			return true
		}
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "invalid_grant") ||
		strings.Contains(msg, "refresh_token_reused") ||
		strings.Contains(msg, "authorization expired") ||
		strings.Contains(msg, "sign in again") ||
		strings.Contains(msg, "unauthorized")
}

func codexSwitchMetadataString(auth *coreauth.Auth, key string) string {
	if auth == nil || auth.Metadata == nil {
		return ""
	}
	if value, ok := auth.Metadata[key].(string); ok {
		return strings.TrimSpace(value)
	}
	return ""
}
