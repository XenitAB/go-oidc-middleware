# Go OpenID Connect (OIDC) HTTP Middleware

[![Coverage Status](https://coveralls.io/repos/github/XenitAB/go-oidc-middleware/badge.svg)](https://coveralls.io/github/XenitAB/go-oidc-middleware)

## Introduction

This is a middleware for http to make it easy to use OpenID Connect.

## Currently Supported frameworks

### Echo (JWT ParseTokenFunc)

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

## Examples

See [Examples readme](examples/README.md) for more information.

## Roadmap

[GitHub Project](https://github.com/XenitAB/go-oidc-middleware/projects/1)
