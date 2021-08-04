# Go OpenID Connect (OIDC) HTTP Middleware

[![Coverage Status](https://coveralls.io/repos/github/XenitAB/go-oidc-middleware/badge.svg)](https://coveralls.io/github/XenitAB/go-oidc-middleware)

## Introduction

This is a middleware for http to make it easy to use OpenID Connect.

## Currently Supported frameworks

### Echo (JWT ParseTokenFunc)

**Middleware**

```go
e.Use(middleware.JWTWithConfig(middleware.JWTConfig{
    ParseTokenFunc: oidc.NewEchoJWTParseTokenFunc(&oidc.Options{
        Issuer:                     cfg.Issuer,
        RequiredTokenType:          "JWT",
        RequiredAudience:           cfg.Audience,
        FallbackSignatureAlgorithm: cfg.FallbackSignatureAlgorithm,
        RequiredClaims: map[string]interface{}{
            "tid": cfg.TenantID,
        },
    }),
}))
```

**Handler**

```go
func getClaimsHandler(c echo.Context) error {
	token, ok := c.Get("user").(jwt.Token)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid token")
	}

	claims, err := token.AsMap(c.Request().Context())
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid token")
	}

	return c.JSON(http.StatusOK, claims)
}
```

### net/http & mux

**Middleware**

```go
oidcHandler := oidc.NewNetHttpHandler(h, &oidc.Options{
    Issuer:                     cfg.Issuer,
    RequiredTokenType:          "JWT",
    RequiredAudience:           cfg.Audience,
    FallbackSignatureAlgorithm: cfg.FallbackSignatureAlgorithm,
    RequiredClaims: map[string]interface{}{
        "tid": cfg.TenantID,
    },
})
```

**Handler**

```go
func getClaimsHandler() http.HandlerFunc {
	fn := func(w http.ResponseWriter, r *http.Request) {
		claims, ok := r.Context().Value(oidc.ClaimsContextKey).(map[string]interface{})
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


## Examples

See [examples readme](examples/README.md) for more information.

## Roadmap

[GitHub Project](https://github.com/XenitAB/go-oidc-middleware/projects/1)
