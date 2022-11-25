package shared

import (
	"fmt"
	"net"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type echoJWTParseTokenFunc func(auth string, c echo.Context) (interface{}, error)

func newEchoJWTClaimsHandler[T any](c echo.Context) error {
	claims, ok := c.Get("user").(T)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid token")
	}

	return c.JSON(http.StatusOK, claims)
}

func RunEchoJWT[T any](parseToken echoJWTParseTokenFunc, address string, port int) error {
	e := echo.New()
	e.HideBanner = true

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.Secure())

	e.Use(middleware.JWTWithConfig(middleware.JWTConfig{
		ParseTokenFunc: parseToken,
	}))

	handler := newEchoJWTClaimsHandler[T]

	e.GET("/", handler)

	addr := net.JoinHostPort(address, fmt.Sprintf("%d", port))
	return e.Start(addr)
}
