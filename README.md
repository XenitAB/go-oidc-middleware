# Go OpenID Connect (OIDC) HTTP Middleware

[![Coverage Status](https://coveralls.io/repos/github/XenitAB/go-oidc-middleware/badge.svg)](https://coveralls.io/github/XenitAB/go-oidc-middleware)

## Introduction

This is a middleware for http to make it easy to use OpenID Connect.

## Stability notice

This library is under active development and the api will have breaking changes until `v0.1.0` - after that only breaking changes will be introduced between minor versions (`v0.1.0` -> `v0.2.0`).

## Currently tested providers

- Azure AD
- Auth0
- Okta
- Cognito

## Currently Supported frameworks

- [Echo (JWT ParseTokenFunc)](https://echo.labstack.com/middleware/jwt/#custom-configuration)
- [net/http](https://pkg.go.dev/net/http), [mux](https://github.com/gorilla/mux) & [chi](https://github.com/go-chi/chi)
- [gin](https://github.com/gin-gonic/gin)
- [fiber](https://github.com/gofiber/fiber)

### Using options

Import: `"github.com/xenitab/go-oidc-middleware/options"`

### Echo (JWT ParseTokenFunc)

**Import**

`"github.com/xenitab/go-oidc-middleware/oidcechojwt"`

**Middleware**

```go
e.Use(middleware.JWTWithConfig(middleware.JWTConfig{
    ParseTokenFunc: oidcechojwt.New(
		options.WithIssuer(cfg.Issuer),
		options.WithRequiredTokenType("JWT"),
		options.WithRequiredAudience(cfg.Audience),
		options.WithFallbackSignatureAlgorithm(cfg.FallbackSignatureAlgorithm),
		options.WithRequiredClaims(map[string]interface{}{
			"tid": cfg.TenantID,
		}),
	),
}))
```

**Handler**

```go
func newClaimsHandler(c echo.Context) error {
	claims, ok := c.Get("user").(map[string]interface{})
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid token")
	}

	return c.JSON(http.StatusOK, claims)
}
```

### net/http, mux & chi

**Import**

`"github.com/xenitab/go-oidc-middleware/oidchttp"`

**Middleware**

```go
oidcHandler := oidchttp.New(h,
	options.WithIssuer(cfg.Issuer),
	options.WithRequiredTokenType("JWT"),
	options.WithRequiredAudience(cfg.Audience),
	options.WithFallbackSignatureAlgorithm(cfg.FallbackSignatureAlgorithm),
	options.WithRequiredClaims(map[string]interface{}{
		"tid": cfg.TenantID,
	}),
)
```

**Handler**

```go
func newClaimsHandler() http.HandlerFunc {
	fn := func(w http.ResponseWriter, r *http.Request) {
		claims, ok := r.Context().Value(options.DefaultClaimsContextKeyName).(map[string]interface{})
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(claims)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	return http.HandlerFunc(fn)
}
```

### gin

**Import**

`"github.com/xenitab/go-oidc-middleware/oidcgin"`

**Middleware**

```go
oidcHandler := oidcgin.New(
	options.WithIssuer(cfg.Issuer),
	options.WithRequiredTokenType("JWT"),
	options.WithRequiredAudience(cfg.Audience),
	options.WithFallbackSignatureAlgorithm(cfg.FallbackSignatureAlgorithm),
	options.WithRequiredClaims(map[string]interface{}{
		"tid": cfg.TenantID,
	}),
)
```

**Handler**

```go
func newClaimsHandler() gin.HandlerFunc {
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
```

### fiber

**Import**

`"github.com/xenitab/go-oidc-middleware/oidcfiber"`

**Middleware**

```go
oidcHandler := oidcfiber.New(
	options.WithIssuer(cfg.Issuer),
	options.WithRequiredTokenType("JWT"),
	options.WithRequiredAudience(cfg.Audience),
	options.WithFallbackSignatureAlgorithm(cfg.FallbackSignatureAlgorithm),
	options.WithRequiredClaims(map[string]interface{}{
		"tid": cfg.TenantID,
	}),
)
```

**Handler**

```go
func newClaimsHandler() fiber.Handler {
	return func(c *fiber.Ctx) error {
		claims, ok := c.Locals("claims").(map[string]interface{})
		if !ok {
			return c.SendStatus(fiber.StatusUnauthorized)
		}

		return c.JSON(claims)
	}
}
```

## Examples

See [examples readme](examples/README.md) for more information.

## Roadmap

[GitHub Project](https://github.com/XenitAB/go-oidc-middleware/projects/1)
