package main

import (
	"examples/shared"
	"fmt"
	"os"

	"github.com/xenitab/go-oidc-middleware/oidchttp"
)

func main() {
	cfg, err := shared.NewOktaConfig()
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

func run(cfg shared.OktaConfig) error {
	h := shared.NewHttpClaimsHandler()
	oidcHandler := oidchttp.New(h, &oidchttp.Options{
		Issuer:                     cfg.Issuer,
		FallbackSignatureAlgorithm: cfg.FallbackSignatureAlgorithm,
		RequiredClaims: map[string]interface{}{
			"cid": cfg.ClientID,
		},
	})

	return shared.RunHttp(oidcHandler, cfg.Address, cfg.Port)
}
