package oidc

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewClaimsCache(t *testing.T) {
	cache := newClaimsCache[string](5 * time.Millisecond)
	randomStrings := []string{}
	for i := 1; i <= 100; i++ {
		randomString := testGenerateRandomString(t, 32)
		randomStrings = append(randomStrings, randomString)
	}

	startGroup := sync.WaitGroup{}
	startGroup.Add(1)
	waitGroup := sync.WaitGroup{}
	for i := 1; i <= 100; i++ {
		waitGroup.Add(2)
		go func() {
			startGroup.Wait()
			for _, s := range randomStrings {
				cache.set(s, s, nil)
				v, err, ok := cache.get(s)
				require.True(t, ok)
				require.Equal(t, s, v)
				require.Nil(t, err)
			}
			waitGroup.Done()
		}()
		go func() {
			startGroup.Wait()
			for _, s := range testReverseSlice(t, randomStrings) {
				cache.set(s, s, nil)
				v, err, ok := cache.get(s)
				require.True(t, ok)
				require.Equal(t, s, v)
				require.Nil(t, err)
			}
			waitGroup.Done()
		}()
	}
	startGroup.Done()
	waitGroup.Wait()
}

func TestNewClaimsCacheExpired(t *testing.T) {
	cache := newClaimsCache[string](10 * time.Millisecond)

	cache.set("foo", "bar", fmt.Errorf("foobar"))
	v1, err1, ok1 := cache.get("foo")
	require.True(t, ok1)
	require.Equal(t, "bar", v1)
	require.ErrorContains(t, err1, "foobar")
	time.Sleep(time.Duration(11) * time.Millisecond)
	v2, err2, ok2 := cache.get("foo")
	require.False(t, ok2)
	require.Empty(t, v2)
	require.Nil(t, err2)

}

func TestTestReverseSlice(t *testing.T) {
	require.Equal(t, []int{5, 4, 3, 2, 1}, testReverseSlice(t, []int{1, 2, 3, 4, 5}))
}

func testReverseSlice[T any](t *testing.T, s []T) []T {
	t.Helper()

	a := make([]T, len(s))
	copy(a, s)

	for i := len(a)/2 - 1; i >= 0; i-- {
		opp := len(a) - 1 - i
		a[i], a[opp] = a[opp], a[i]
	}

	return a
}

func testGenerateRandomString(t *testing.T, n int) string {
	t.Helper()

	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		require.NoError(t, err)
		ret[i] = letters[num.Int64()]
	}

	return string(ret)
}
