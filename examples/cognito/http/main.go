package main

import (
	"examples/shared"
	"fmt"
	"os"

	"github.com/xenitab/go-oidc-middleware/oidchttp"
	"github.com/xenitab/go-oidc-middleware/options"
)

func main() {
	cfg, err := shared.NewCognitoConfig()
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

func run(cfg shared.CognitoConfig) error {
	h := shared.NewHttpClaimsHandler()
	oidcHandler := oidchttp.New(h,
		options.WithIssuer(cfg.Issuer),
		options.WithFallbackSignatureAlgorithm(cfg.FallbackSignatureAlgorithm),
		options.WithRequiredClaims(map[string]interface{}{
			"client_id": cfg.ClientID,
		}),
	)

	return shared.RunHttp(oidcHandler, cfg.Address, cfg.Port)
}
