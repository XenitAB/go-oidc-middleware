package main

import (
	"examples/shared"
	"fmt"
	"os"

	"github.com/xenitab/go-oidc-middleware/oidcgin"
)

func main() {
	cfg, err := shared.NewAuth0Config()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	err = run(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "application returned error: %v\n", err)
		os.Exit(1)
	}
}

func run(cfg shared.Auth0Config) error {
	oidcHandler := oidcgin.New(&oidcgin.Options{
		Issuer:                     cfg.Issuer,
		RequiredTokenType:          "JWT",
		RequiredAudience:           cfg.Audience,
		FallbackSignatureAlgorithm: cfg.FallbackSignatureAlgorithm,
		RequiredClaims: map[string]interface{}{
			"azp": cfg.ClientID,
		},
	})

	return shared.RunGin(oidcHandler, cfg.Address, cfg.Port)
}
