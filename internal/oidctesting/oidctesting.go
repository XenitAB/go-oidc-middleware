package oidctesting

import (
	"fmt"
	"net/http"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func BenchmarkConcurrent(b *testing.B, getToken func(t testing.TB) *oauth2.Token, fn func(token *oauth2.Token)) {
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

func TestHttpRequest(tb testing.TB, urlString string, token *oauth2.Token) {
	tb.Helper()

	req, err := http.NewRequest(http.MethodGet, urlString, nil)
	require.NoError(tb, err)
	token.SetAuthHeader(req)
	res, err := http.DefaultClient.Do(req)
	require.NoError(tb, err)

	defer require.NoError(tb, res.Body.Close())

	require.Equal(tb, http.StatusOK, res.StatusCode)
}
