module examples

go 1.16

require (
	github.com/cristalhq/aconfig v0.16.2
	github.com/labstack/echo/v4 v4.5.0
	github.com/lestrrat-go/jwx v1.2.4
	github.com/pkg/browser v0.0.0-20210706143420-7d21f8c997e2
	github.com/xenitab/go-oidc-middleware v0.0.0-00010101000000-000000000000
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
)

replace github.com/xenitab/go-oidc-middleware => ../
