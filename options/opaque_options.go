package options

import (
	"net/http"
	"time"
)

type OpaqueOptions struct {
	Issuer                string
	DiscoveryUri          string
	DiscoveryFetchTimeout time.Duration
	UserinfoUri           string
	UserinfoFetchTimeout  time.Duration
	TokenTTL              time.Duration
	RequiredClaims        map[string]interface{}
	HttpClient            *http.Client
	ClaimsContextKeyName  ClaimsContextKeyName
	ErrorHandler          ErrorHandler
}

func NewOpaque(setters ...OpaqueOption) *OpaqueOptions {
	opts := &OpaqueOptions{
		DiscoveryFetchTimeout: 5 * time.Second,
		UserinfoFetchTimeout:  5 * time.Second,
		HttpClient:            http.DefaultClient,
		ClaimsContextKeyName:  DefaultClaimsContextKeyName,
	}

	for _, setter := range setters {
		setter(opts)
	}

	return opts
}

type OpaqueOption func(*OpaqueOptions)
