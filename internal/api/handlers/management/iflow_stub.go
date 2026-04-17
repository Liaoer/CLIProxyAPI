package management

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// RequestIFlowToken is a temporary compatibility stub for a route that is
// registered by the server but has no provider implementation in this tree.
func (h *Handler) RequestIFlowToken(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "iflow auth flow is not implemented in this build",
	})
}

// RequestIFlowCookieToken is a temporary compatibility stub for the cookie
// variant of the iflow auth route.
func (h *Handler) RequestIFlowCookieToken(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "iflow cookie auth flow is not implemented in this build",
	})
}
