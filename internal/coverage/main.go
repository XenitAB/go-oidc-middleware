package coverage

import (
	"net/http"

	"github.com/xenitab/go-oidc-middleware/oidcechojwt"
	"github.com/xenitab/go-oidc-middleware/oidcfiber"
	"github.com/xenitab/go-oidc-middleware/oidcgin"
	"github.com/xenitab/go-oidc-middleware/oidchttp"
	"github.com/xenitab/go-oidc-middleware/optest"
	"github.com/xenitab/go-oidc-middleware/options"
)

func main() {
	f := &foo{}
	_ = oidcechojwt.New[*optest.TestUser]()
	_ = oidcfiber.New[*optest.TestUser]()
	_ = oidcgin.New[*optest.TestUser]()
	_ = oidchttp.New[*optest.TestUser](f)
	_ = options.New()
}

type foo struct{}

func (f *foo) ServeHTTP(http.ResponseWriter, *http.Request) {}
