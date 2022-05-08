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

- [net/http](https://pkg.go.dev/net/http), [mux](https://github.com/gorilla/mux) & [chi](https://github.com/go-chi/chi)
- [gin](https://github.com/gin-gonic/gin)
- [fiber](https://github.com/gofiber/fiber)
- [Echo (JWT ParseTokenFunc)](https://echo.labstack.com/middleware/jwt/#custom-configuration)
- Build your own middleware

### Using options

Import: `"github.com/xenitab/go-oidc-middleware/options"`

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

### Build your own middleware

**Import**

`"github.com/xenitab/go-oidc-middleware/oidctoken"`

**Example**

```go
oidcTokenHandler := oidctoken.New(h,
	options.WithIssuer(cfg.Issuer),
	options.WithRequiredTokenType("JWT"),
	options.WithRequiredAudience(cfg.Audience),
	options.WithFallbackSignatureAlgorithm(cfg.FallbackSignatureAlgorithm),
	options.WithRequiredClaims(map[string]interface{}{
		"tid": cfg.TenantID,
	}),
)

// oidctoken.GetTokenString is optional, but you will need the JWT token as a string
tokenString, err := oidctoken.GetTokenString(...)
if err != nil {
	panic(err)
}

token, err := oidcTokenHandler.ParseToken(ctx, tokenString)
if err != nil {
	panic(err)
}
```

## Other options

### Deeply nested required claims

If you want to use `options.WithRequiredClaims()` with nested values, you need to specify the actual type when configuring it and not an interface and the middleware will use this to infer what types the token claims are.

Example claims could look like this:

```json
{
  "foo": {
    "bar": ["uno", "dos", "baz", "tres"]
  }
}
```

This would then be interpreted as the following inside the code:

```go
"foo": map[string]interface {}{
	"bar":[]interface {}{
		"uno",
		"dos",
		"baz",
		"tres"
	},
}
```

If you want to require the claim `foo.bar` to contain the value `baz`, it would look like this:

```go
options.WithRequiredClaims(map[string]interface{}{
	"foo": map[string][]string{
		"bar": {"baz"},
	}
})
```

### Extract token from multiple headers

Example for `Authorization` and `Foo` headers. If token is found in `Authorization`, `Foo` will not be tried. If `Authorization` extraction fails but there's a header `Foo = Bar_baz` then `baz` would be extracted as the token.

```go
oidcHandler := oidcgin.New(
	options.WithIssuer(cfg.Issuer),
	options.WithFallbackSignatureAlgorithm(cfg.FallbackSignatureAlgorithm),
	options.WithRequiredClaims(map[string]interface{}{
		"cid": cfg.ClientID,
	}),
	options.WithTokenString(
		options.WithTokenStringHeaderName("Authorization"),
		options.WithTokenStringTokenPrefix("Bearer "),
	),
	options.WithTokenString(
		options.WithTokenStringHeaderName("Foo"),
		options.WithTokenStringTokenPrefix("Bar_"),
	),
)
```

### Manipulate the token string after extraction

If you want to do any kind of manipulation of the token string after extraction, the option `WithTokenStringPostExtractionFn` is available.

The following would be used by a the Kubernetes api server, where the kubernetes client can use both `Authorization` and `Sec-WebSocket-Protocol`.

```go
oidcHandler := oidcgin.New(
	options.WithIssuer(cfg.Issuer),
	options.WithFallbackSignatureAlgorithm(cfg.FallbackSignatureAlgorithm),
	options.WithRequiredClaims(map[string]interface{}{
		"cid": cfg.ClientID,
	}),
	options.WithTokenString(
		options.WithTokenStringHeaderName("Authorization"),
		options.WithTokenStringTokenPrefix("Bearer "),
	),
	options.WithTokenString(
		options.WithTokenStringHeaderName("Sec-WebSocket-Protocol"),
		options.WithTokenStringTokenPrefix("base64url.bearer.authorization.k8s.io."),
		options.WithTokenStringListSeparator(","),
		options.WithTokenStringPostExtractionFn(func(s string) (string, error) {
			bytes, err := base64.RawStdEncoding.DecodeString(s)
			if err != nil {
				return "", err
			}

			return string(bytes), nil
		}),
	),
)
```

### Custom error handler

It is possible to add a custom function to handle errors. It will not be possible to change anything using it, but you will be able to add logic for logging as an example.

```go
errorHandler := func(description options.ErrorDescription, err error) {
	fmt.Printf("Description: %s\tError: %v\n", description, err)
}

oidcHandler := oidcgin.New(
	options.WithIssuer(cfg.Issuer),
	options.WithFallbackSignatureAlgorithm(cfg.FallbackSignatureAlgorithm),
	options.WithRequiredClaims(map[string]interface{}{
		"cid": cfg.ClientID,
	}),
	options.WithErrorHandler(errorHandler),
)
```

### Testing with the middleware enabled

There's a small package that simulates an OpenID Provider that can be used with tests.

```go
package main

import (
	"testing"

	"github.com/xenitab/go-oidc-middleware/optest"
)

func TestFoobar(t *testing.T) {
	op := optest.NewTesting(t)
	defer op.Close(t)

	[...]

	oidcHandler := oidchttp.New(h,
		options.WithIssuer(op.GetURL(t)),
		options.WithRequiredTokenType("JWT+AT"),
		options.WithRequiredAudience("test-client"),
	)

	token := op.GetToken(t)

	[...]

	token.SetAuthHeader(req)

	[...]
}
```

You can also configure multiple users by setting the following:

```go
func TestFoobar(t *testing.T) {
	testUsers := map[string]TestUser{
		"test": {
			Audience:           "test-client",
			Subject:            "test",
			Name:               "Test Testersson",
			GivenName:          "Test",
			FamilyName:         "Testersson",
			Locale:             "en-US",
			Email:              "test@testersson.com",
			AccessTokenKeyType: "JWT+AT",
			IdTokenKeyType:     "JWT",
		},
		"foo": {
			Audience:           "foo-client",
			Subject:            "foo",
			Name:               "Foo Bar",
			GivenName:          "Foo",
			FamilyName:         "Bar",
			Locale:             "en-US",
			Email:              "foo@bar.com",
			AccessTokenKeyType: "JWT+AT",
			IdTokenKeyType:     "JWT",
		},
	}

	op := optest.NewTesting(t, optest.WithTestUsers(testUsers), optest.WithDefaultTestUser("test"))
	defer op.Close(t)

	[...]

	token1 := op.GetToken(t) // for user `test`
	token2 := op.GetTokenByUser(t, "test") // for user `test`
	token3 := op.GetTokenByUser(t, "foo") // for user `foo`
}
```

## Examples

See [examples readme](examples/README.md) for more information.

## Roadmap

[GitHub Project](https://github.com/XenitAB/go-oidc-middleware/projects/1)
