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

func (c *testClaims) Validate() error {
	return nil
}

func main() {
	f := &foo{}
	_ = oidcechojwt.New[*testClaims]()
	_ = oidcfiber.New[*testClaims]()
	_ = oidcgin.New[*testClaims]()
	_ = oidchttp.New[*testClaims](f)
	_ = options.New()
}

type foo struct{}

func (f *foo) ServeHTTP(http.ResponseWriter, *http.Request) {}
