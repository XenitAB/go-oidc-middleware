package coverage

import (
	"net/http"

	"github.com/xenitab/go-oidc-middleware/oidcechojwt"
	"github.com/xenitab/go-oidc-middleware/oidcfiber"
	"github.com/xenitab/go-oidc-middleware/oidcgin"
	"github.com/xenitab/go-oidc-middleware/oidchttp"
	"github.com/xenitab/go-oidc-middleware/options"
)

type testClaims map[string]interface{}

func main() {
	f := &foo{}
	_ = oidcechojwt.New[testClaims](nil)
	_ = oidcfiber.New[testClaims](nil)
	_ = oidcgin.New[testClaims](nil)
	_ = oidchttp.New[testClaims](f, nil)
	_ = options.New()
}

type foo struct{}

func (f *foo) ServeHTTP(http.ResponseWriter, *http.Request) {}
