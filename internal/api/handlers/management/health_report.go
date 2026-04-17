package management

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/diagnostics"
)

// HealthReport returns a structured, read-only diagnostics snapshot for the management UI.
func (h *Handler) HealthReport(c *gin.Context) {
	if h == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "handler not initialized"})
		return
	}
	report, err := diagnostics.Generate(c.Request.Context(), diagnostics.Options{
		AuthManager:         h.authManager,
		ActiveCodexAuthPath: h.codexActiveAuthPath,
		AuthID:              strings.TrimSpace(c.Query("auth_id")),
		Deep:                strings.EqualFold(strings.TrimSpace(c.Query("deep")), "true") || strings.TrimSpace(c.Query("deep")) == "1",
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, report)
}
