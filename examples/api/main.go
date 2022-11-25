package main

import (
	"examples/shared"
	"fmt"
	"os"

	"github.com/xenitab/go-oidc-middleware/oidcechojwt"
	"github.com/xenitab/go-oidc-middleware/oidcfiber"
	"github.com/xenitab/go-oidc-middleware/oidcgin"
	"github.com/xenitab/go-oidc-middleware/oidchttp"
	"github.com/xenitab/go-oidc-middleware/options"
)

func main() {
	runtimeCfg, err := shared.NewRuntimeConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load runtime config: %v\n", err)
		os.Exit(1)
	}

	err = run(runtimeCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "application returned error: %v\n", err)
		os.Exit(1)
	}
}

func run(cfg shared.RuntimeConfig) error {
	var opts []options.Option

	// requiredClaims := make(*optest.TestUser)
	// for k, v := range cfg.RequiredClaims {
	// 	requiredClaims[k] = v
	// }

	switch cfg.Provider {
	case shared.Auth0Provider:
		inputs := map[string]string{
			"issuer":                     cfg.Issuer,
			"audience":                   cfg.Audience,
			"fallbackSignatureAlgorithm": cfg.FallbackSignatureAlgorithm,
			"requiredClaims azp":         cfg.RequiredClaims["azp"],
		}

		err := stringNotEmpty(inputs)
		if err != nil {
			return err
		}

		opts = []options.Option{
			options.WithIssuer(cfg.Issuer),
			options.WithRequiredTokenType("JWT"),
			options.WithRequiredAudience(cfg.Audience),
			options.WithFallbackSignatureAlgorithm(cfg.FallbackSignatureAlgorithm),
			// FIXME: Add required claims
			// options.WithRequiredClaims(requiredClaims),
		}
	case shared.AzureADProvider:
		inputs := map[string]string{
			"issuer":                     cfg.Issuer,
			"audience":                   cfg.Audience,
			"fallbackSignatureAlgorithm": cfg.FallbackSignatureAlgorithm,
			"requiredClaims tid":         cfg.RequiredClaims["tid"],
		}

		err := stringNotEmpty(inputs)
		if err != nil {
			return err
		}

		opts = []options.Option{
			options.WithIssuer(cfg.Issuer),
			options.WithRequiredTokenType("JWT"),
			options.WithRequiredAudience(cfg.Audience),
			options.WithFallbackSignatureAlgorithm(cfg.FallbackSignatureAlgorithm),
			// FIXME: Remove when token validation is added
			// options.WithRequiredClaims(requiredClaims),
		}
	case shared.CognitoProvider:
		inputs := map[string]string{
			"issuer":                     cfg.Issuer,
			"fallbackSignatureAlgorithm": cfg.FallbackSignatureAlgorithm,
			"requiredClaims client_id":   cfg.RequiredClaims["client_id"],
		}

		err := stringNotEmpty(inputs)
		if err != nil {
			return err
		}

		opts = []options.Option{
			options.WithIssuer(cfg.Issuer),
			options.WithFallbackSignatureAlgorithm(cfg.FallbackSignatureAlgorithm),
			// FIXME: Remove when token validation is added
			// options.WithRequiredClaims(requiredClaims),
		}
	case shared.OktaProvider:
		inputs := map[string]string{
			"issuer":                     cfg.Issuer,
			"fallbackSignatureAlgorithm": cfg.FallbackSignatureAlgorithm,
			"requiredClaims cid":         cfg.RequiredClaims["cid"],
		}

		err := stringNotEmpty(inputs)
		if err != nil {
			return err
		}

		opts = []options.Option{
			options.WithIssuer(cfg.Issuer),
			options.WithFallbackSignatureAlgorithm(cfg.FallbackSignatureAlgorithm),
			// FIXME: Remove when token validation is added
			// options.WithRequiredClaims(requiredClaims),
		}
	default:
		return fmt.Errorf("unknown provider: %s", cfg.Provider)
	}

	switch cfg.Server {
	case shared.HttpServer:
		h := shared.NewHttpClaimsHandler()
		oidcHandler := oidchttp.New[*shared.Claims](h, opts...)

		return shared.RunHttp(oidcHandler, cfg.Address, cfg.Port)
	case shared.GinServer:
		oidcHandler := oidcgin.New[*shared.Claims](opts...)

		return shared.RunGin(oidcHandler, cfg.Address, cfg.Port)
	case shared.EchoJwtServer:
		parseToken := oidcechojwt.New[*shared.Claims](opts...)

		return shared.RunEchoJWT(parseToken, cfg.Address, cfg.Port)
	case shared.FiberServer:
		oidcHandler := oidcfiber.New[*shared.Claims](opts...)

		return shared.RunFiber(oidcHandler, cfg.Address, cfg.Port)
	default:
		return fmt.Errorf("unknown server: %s", cfg.Server)
	}
}

func stringNotEmpty(input map[string]string) error {
	for k, v := range input {
		if v == "" {
			return fmt.Errorf("value for %s is empty", k)
		}
	}

	return nil
}
