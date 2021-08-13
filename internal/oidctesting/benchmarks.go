package oidctesting

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xenitab/dispans/server"
	"github.com/xenitab/go-oidc-middleware/options"
	"golang.org/x/oauth2"
)

func RunBenchmarks(b *testing.B, testName string, newHandlerFn newHandlerFn) {
	b.Helper()

	runBenchmarkHandler(b, testName, newHandlerFn)
	runBenchmarkRequirements(b, testName, newHandlerFn)
	runBenchmarkHttp(b, testName, newHandlerFn)
}

func runBenchmarkHandler(b *testing.B, testName string, newHandlerFn newHandlerFn) {
	b.Helper()

	b.Run(fmt.Sprintf("%s_handler", testName), func(b *testing.B) {
		op := server.NewTesting(b)
		defer op.Close(b)

		handler := newHandlerFn(
			options.WithIssuer(op.GetURL(b)),
		)

		fn := func(token *oauth2.Token) {
			testHttpWithAuthentication(b, token, handler)
		}

		runBenchmarkConcurrent(b, op.GetToken, fn)
	})
}

func runBenchmarkRequirements(b *testing.B, testName string, newHandlerFn newHandlerFn) {
	b.Helper()

	b.Run(fmt.Sprintf("%s_requirements", testName), func(b *testing.B) {
		op := server.NewTesting(b)
		defer op.Close(b)

		handler := newHandlerFn(
			options.WithIssuer(op.GetURL(b)),
			options.WithRequiredTokenType("JWT+AT"),
			options.WithRequiredAudience("test-client"),
			options.WithRequiredClaims(map[string]interface{}{
				"sub": "test",
			}),
		)

		fn := func(token *oauth2.Token) {
			testHttpWithAuthentication(b, token, handler)
		}

		runBenchmarkConcurrent(b, op.GetToken, fn)
	})
}

func runBenchmarkHttp(b *testing.B, testName string, newHandlerFn newHandlerFn) {
	b.Helper()

	b.Run(fmt.Sprintf("%s_http", testName), func(b *testing.B) {
		op := server.NewTesting(b)
		defer op.Close(b)

		handler := newHandlerFn(
			options.WithIssuer(op.GetURL(b)),
		)

		testServer := httptest.NewServer(handler)
		defer testServer.Close()

		fn := func(token *oauth2.Token) {
			benchmarkHttpRequest(b, testServer.URL, token)
		}

		runBenchmarkConcurrent(b, op.GetToken, fn)
	})
}

func runBenchmarkConcurrent(b *testing.B, getToken func(t testing.TB) *oauth2.Token, fn func(token *oauth2.Token)) {
	b.Helper()

	concurrencyLevels := []int{5, 10, 20, 50}
	for _, clients := range concurrencyLevels {
		numClients := clients
		b.Run(fmt.Sprintf("%d_clients", numClients), func(b *testing.B) {
			var tokens []*oauth2.Token
			for i := 0; i < b.N; i++ {
				tokens = append(tokens, getToken(b))
			}

			b.ResetTimer()

			var wg sync.WaitGroup
			ch := make(chan int, numClients)
			for i := 0; i < b.N; i++ {
				token := tokens[i]
				wg.Add(1)
				ch <- 1
				go func() {
					defer wg.Done()
					fn(token)
					<-ch
				}()
			}
			wg.Wait()
		})
	}
}

func benchmarkHttpRequest(tb testing.TB, urlString string, token *oauth2.Token) {
	tb.Helper()

	req, err := http.NewRequest(http.MethodGet, urlString, nil)
	require.NoError(tb, err)
	token.SetAuthHeader(req)
	res, err := http.DefaultClient.Do(req)
	require.NoError(tb, err)

	defer require.NoError(tb, res.Body.Close())

	require.Equal(tb, http.StatusOK, res.StatusCode)
}
