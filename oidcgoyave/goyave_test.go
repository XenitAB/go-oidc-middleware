package oidcgoyave

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xenitab/go-oidc-middleware/internal/oidc"
	"github.com/xenitab/go-oidc-middleware/internal/oidctesting"
	"github.com/xenitab/go-oidc-middleware/options"
	"gorm.io/gorm"

	"goyave.dev/goyave/v4"
	"goyave.dev/goyave/v4/auth"
	"goyave.dev/goyave/v4/database"
	_ "goyave.dev/goyave/v4/database/dialect/sqlite"
)

const testName = "OidcGoyave"

func TestSuite(t *testing.T) {
	goyave.RunTest(t, new(OIDCAuthenticatorTestSuite))
}

// func BenchmarkSuite(b *testing.B) {
// 	oidctesting.RunBenchmarks(b, testName, newTestHandler(b))
// }

type TestUser struct {
	gorm.Model
	Name     string `gorm:"type:varchar(100)"`
	Password string `gorm:"type:varchar(100)" auth:"password"`
	Email    string `gorm:"type:varchar(100);uniqueIndex" auth:"username"`
}

func testGetGoyaveRouter(tb testing.TB, a *OIDCAuthenticator) *goyave.Router {
	tb.Helper()

	router := goyave.NewRouter()
	router.Middleware(auth.Middleware(&TestUser{}, a))
	router.Get("/", func(res *goyave.Response, req *goyave.Request) {
		claims, ok := req.Extra["jwt_claims"].(map[string]interface{})
		if !ok {
			res.Status(http.StatusUnauthorized)
			return
		}

		res.JSON(http.StatusOK, claims)
	})

	return router
}

type testServer struct {
	tb     testing.TB
	server *httptest.Server
}

func newTestServer(tb testing.TB, router *goyave.Router) *testServer {
	tb.Helper()

	server := httptest.NewServer(router)

	return &testServer{
		tb:     tb,
		server: server,
	}
}

func (srv *testServer) Close() {
	srv.tb.Helper()

	srv.server.Close()
}

func (srv *testServer) URL() string {
	srv.tb.Helper()

	return srv.server.URL
}

type testHandler struct {
	tb testing.TB
}

func newTestHandler(tb testing.TB) *testHandler {
	tb.Helper()

	return &testHandler{
		tb: tb,
	}
}

func (h *testHandler) NewHandlerFn(opts ...options.Option) http.Handler {
	h.tb.Helper()

	a := New("sub", opts...)
	router := testGetGoyaveRouter(h.tb, a)

	return router
}

func (h *testHandler) ToHandlerFn(parseToken oidc.ParseTokenFunc, opts ...options.Option) http.Handler {
	h.tb.Helper()

	a := &OIDCAuthenticator{
		parseToken: parseToken,
		opts:       options.New(opts...),
		claimName:  "sub",
	}

	router := testGetGoyaveRouter(h.tb, a)

	return router
}

func (h *testHandler) NewTestServer(opts ...options.Option) oidctesting.ServerTester {
	h.tb.Helper()

	a := New("sub", opts...)
	app := testGetGoyaveRouter(h.tb, a)

	return newTestServer(h.tb, app)
}

type OIDCAuthenticatorTestSuite struct {
	user *TestUser
	goyave.TestSuite
}

func (suite *OIDCAuthenticatorTestSuite) SetupSuite() {
	// database.RegisterDialect("my-driver", "{username}:{password}@({host}:{port})/{name}?{options}", mydriver.Open)
	database.ClearRegisteredModels()
	database.RegisterModel(&TestUser{})

	database.Migrate()
}

func (suite *OIDCAuthenticatorTestSuite) SetupTest() {
	suite.user = &TestUser{
		Name:  "Admin",
		Email: "johndoe@example.org",
	}

	database.GetConnection().Create(suite.user)
}

func (suite *OIDCAuthenticatorTestSuite) TestOidcGoyave() {
	t := suite.T()
	oidctesting.RunTests(t, testName, newTestHandler(t))
}

func (suite *OIDCAuthenticatorTestSuite) TearDownTest() {
	suite.ClearDatabase()
}

func (suite *OIDCAuthenticatorTestSuite) TearDownSuite() {
	database.Conn().Migrator().DropTable(&TestUser{})
	database.ClearRegisteredModels()
}
