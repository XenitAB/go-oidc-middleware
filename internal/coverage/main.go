package coverage

import (
	"net/http"

	"github.com/xenitab/go-oidc-middleware/oidcechojwt"
	"github.com/xenitab/go-oidc-middleware/oidcfiber"
	"github.com/xenitab/go-oidc-middleware/oidcgin"
	"github.com/xenitab/go-oidc-middleware/oidchttp"
	"github.com/xenitab/go-oidc-middleware/options"
)

func main() {
	f := &foo{}
	_ = oidcechojwt.New()
	_ = oidcfiber.New()
	_ = oidcgin.New()
	_ = oidchttp.New(f)
	_ = options.New()
}

type foo struct{}

func (f *foo) ServeHTTP(http.ResponseWriter, *http.Request) {}
