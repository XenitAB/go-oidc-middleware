package shared

import (
	"fmt"
	"net"
	"net/http"

	"github.com/gin-gonic/gin"
)

func newGinClaimsHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		claimsValue, found := c.Get("claims")
		if !found {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		claims, ok := claimsValue.(map[string]interface{})
		if !ok {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		c.JSON(http.StatusOK, claims)
	}
}

func RunGin(oidcHandler gin.HandlerFunc, address string, port int) error {
	addr := net.JoinHostPort(address, fmt.Sprintf("%d", port))

	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	r.Use(oidcHandler)

	claimsHandler := newGinClaimsHandler()
	r.GET("/", claimsHandler)

	return r.Run(addr)
}
