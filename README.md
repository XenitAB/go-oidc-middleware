# Go OpenID Connect (OIDC) HTTP Middleware

[![Coverage Status](https://coveralls.io/repos/github/XenitAB/go-oidc-middleware/badge.svg)](https://coveralls.io/github/XenitAB/go-oidc-middleware)

## Introduction

This is a middleware for http to make it easy to use OpenID Connect.

## Changelog

Below, large (breaking) changes will be documented:

### v0.0.37

From `v0.0.37` and forward, the `options.WithRequiredClaims()` has been deprecated and generics are used to provide the claims type. A new validation function can be provided instead of `options.WithRequiredClaims()`. If you don't need claims validation, you can pass `nil` instead of a `ClaimsValidationFn`.

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

### Claims validation example

From `v0.0.37` and forward, claim validation is done using a `ClaimsValidationFn`. The below examples will use the following claims type and validation function:

```go
type AzureADClaims struct {
	Aio               string    `json:"aio"`
	Audience          []string  `json:"aud"`
	Azp               string    `json:"azp"`
	Azpacr            string    `json:"azpacr"`
	ExpiresAt         time.Time `json:"exp"`
	IssuedAt          time.Time `json:"iat"`
	Idp               string    `json:"idp"`
	Issuer            string    `json:"iss"`
	Name              string    `json:"name"`
	NotBefore         time.Time `json:"nbf"`
	Oid               string    `json:"oid"`
	PreferredUsername string    `json:"preferred_username"`
	Rh                string    `json:"rh"`
	Scope             string    `json:"scp"`
	Subject           string    `json:"sub"`
	TenantId          string    `json:"tid"`
	Uti               string    `json:"uti"`
	TokenVersion      string    `json:"ver"`
}

func GetAzureADClaimsValidationFn(requiredTenantId string) options.ClaimsValidationFn[AzureADClaims] {
	return func(claims *AzureADClaims) error {
		if requiredTenantId != "" && claims.TenantId != requiredTenantId {
			return fmt.Errorf("tid claim is required to be %q but was: %s", requiredTenantId, claims.TenantId)
		}

		return nil
	}
}
```

If you don't want typed claims, use `type Claims map[string]interface{}` and provide it. If you don't want to use a `ClaimsValidationFn` (as it will provide the type) the handlers will need to be configured as below:

```go
type Claims map[string]interface{}

oidcHandler := oidchttp.New[Claims](h, nil, opts...)
```

or

```go
oidcHandler := oidchttp.New[map[string]interface{}](h, nil, opts...)
```

### net/http, mux & chi

**Import**

`"github.com/xenitab/go-oidc-middleware/oidchttp"`

**Middleware**

```go
oidcHandler := oidchttp.New(h,
	GetAzureADClaimsValidationFn(cfg.TenantID),
	options.WithIssuer(cfg.Issuer),
	options.WithRequiredTokenType("JWT"),
	options.WithRequiredAudience(cfg.Audience),
	options.WithFallbackSignatureAlgorithm(cfg.FallbackSignatureAlgorithm),
)
```

**Handler**

```go
func newClaimsHandler() http.HandlerFunc {
	fn := func(w http.ResponseWriter, r *http.Request) {
		claims, ok := r.Context().Value(options.DefaultClaimsContextKeyName).(AzureADClaims)
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
	GetAzureADClaimsValidationFn(cfg.TenantID),
	options.WithIssuer(cfg.Issuer),
	options.WithRequiredTokenType("JWT"),
	options.WithRequiredAudience(cfg.Audience),
	options.WithFallbackSignatureAlgorithm(cfg.FallbackSignatureAlgorithm),
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

		claims, ok := claimsValue.(AzureADClaims)
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
	GetAzureADClaimsValidationFn(cfg.TenantID),
	options.WithIssuer(cfg.Issuer),
	options.WithRequiredTokenType("JWT"),
	options.WithRequiredAudience(cfg.Audience),
	options.WithFallbackSignatureAlgorithm(cfg.FallbackSignatureAlgorithm),
)
```

**Handler**

```go
func newClaimsHandler() fiber.Handler {
	return func(c *fiber.Ctx) error {
		claims, ok := c.Locals("claims").(AzureADClaims)
		if !ok {
			return c.SendStatus(fiber.StatusUnauthorized)
		}

		return c.JSON(claims)
	}
}
```

### Echo (JWT ParseTokenFunc)

**Import**

`"github.com/xenitab/go-oidc-middleware/oidcecho"`

**Middleware**

```go
e.Use(middleware.JWTWithConfig(middleware.JWTConfig{
    ParseTokenFunc: oidcecho.New(
		GetAzureADClaimsValidationFn(cfg.TenantID),
		options.WithIssuer(cfg.Issuer),
		options.WithRequiredTokenType("JWT"),
		options.WithRequiredAudience(cfg.Audience),
		options.WithFallbackSignatureAlgorithm(cfg.FallbackSignatureAlgorithm),
	),
}))
```

**Handler**

```go
func newClaimsHandler(c echo.Context) error {
	claims, ok := c.Get("user").(AzureADClaims)
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
	GetAzureADClaimsValidationFn(cfg.TenantID),
	options.WithIssuer(cfg.Issuer),
	options.WithRequiredTokenType("JWT"),
	options.WithRequiredAudience(cfg.Audience),
	options.WithFallbackSignatureAlgorithm(cfg.FallbackSignatureAlgorithm),
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

### Extract token from multiple headers

Example for `Authorization` and `Foo` headers. If token is found in `Authorization`, `Foo` will not be tried. If `Authorization` extraction fails but there's a header `Foo = Bar_baz` then `baz` would be extracted as the token.

```go
oidcHandler := oidcgin.New(
	GetAzureADClaimsValidationFn(cfg.TenantID),
	options.WithIssuer(cfg.Issuer),
	options.WithFallbackSignatureAlgorithm(cfg.FallbackSignatureAlgorithm),
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
	GetAzureADClaimsValidationFn(cfg.TenantID),
	options.WithIssuer(cfg.Issuer),
	options.WithFallbackSignatureAlgorithm(cfg.FallbackSignatureAlgorithm),
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

It is possible to add a custom function to handle errors. The error handler can return an `options.Response` which will be rendered by the middleware. Returning `nil` will result in a default 400/401 error.

```go
type Message struct {
	Message string `json:"message"`
	Url     string `json:"url"`
}

func errorHandler(ctx context.Context, oidcErr *options.OidcError) *options.Response {
	message := Message{
		Message: string(oidcErr.Status),
		Url:     oidcErr.Url.String(),
	}
	var headers map[string]string
	json, err := json.Marshal(message)
	if err != nil {
		headers["Content-Type"] = "text/plain"
		return &options.Response{
			StatusCode: 500,
			Headers:    headers,
			Body:       []byte("Internal encoding failure\r\n"),
		}
	}
	headers["Content-Type"] = "text/plain"
	return &options.Response{
		StatusCode: 418,
		Headers:    headers,
		Body:       json,
	}
}

oidcHandler := oidcgin.New(
	GetAzureADClaimsValidationFn(cfg.TenantID),
	options.WithIssuer(cfg.Issuer),
	options.WithFallbackSignatureAlgorithm(cfg.FallbackSignatureAlgorithm),
	options.WithErrorHandler(errorHandler),
)
```

This error handling interface was changed in v0.0.42. The previous interface was `func(description ErrorDescription, err error)`. In order to retain the same behavior, you need to update your error handler to read `desctiption` and `err` from `oidcErr` and return `nil`.

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
		GetAzureADClaimsValidationFn(cfg.TenantID),
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

It is also possible to enable opaque access tokens with the option `optest.WithOpaqueAccessTokens()`. If you add `optest.WithLoginPrompt()` you will have a simple HTML page with the different test users to choose from when going to `/authorization`.

## Examples

See [examples readme](examples/README.md) for more information.

## Roadmap

[GitHub Project](https://github.com/XenitAB/go-oidc-middleware/projects/1)
