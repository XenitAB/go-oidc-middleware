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

	switch cfg.Provider {
	case shared.Auth0Provider:
		inputs := map[string]string{
			"issuer":                     cfg.Issuer,
			"audience":                   cfg.Audience,
			"fallbackSignatureAlgorithm": cfg.FallbackSignatureAlgorithm,
			// "requiredClaims azp":         cfg.RequiredClaims["azp"],
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
		shared.GlobalRequiredAuth0AzpClaim = cfg.ClientID
		return getHandler[*shared.Auth0Claims](cfg, opts...)
	case shared.AzureADProvider:
		inputs := map[string]string{
			"issuer":                     cfg.Issuer,
			"audience":                   cfg.Audience,
			"fallbackSignatureAlgorithm": cfg.FallbackSignatureAlgorithm,
			// "requiredClaims tid":         cfg.RequiredClaims["tid"],
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
		return getHandler[*shared.Claims](cfg, opts...)
	case shared.CognitoProvider:
		inputs := map[string]string{
			"issuer":                     cfg.Issuer,
			"fallbackSignatureAlgorithm": cfg.FallbackSignatureAlgorithm,
			// "requiredClaims client_id":   cfg.RequiredClaims["client_id"],
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
		return getHandler[*shared.Claims](cfg, opts...)
	case shared.OktaProvider:
		inputs := map[string]string{
			"issuer":                     cfg.Issuer,
			"fallbackSignatureAlgorithm": cfg.FallbackSignatureAlgorithm,
			// "requiredClaims cid":         cfg.RequiredClaims["cid"],
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
		return getHandler[*shared.Claims](cfg, opts...)
	default:
		return fmt.Errorf("unknown provider: %s", cfg.Provider)
	}
}

type ClaimsValidator interface {
	Validate() error
}

func getHandler[T ClaimsValidator](cfg shared.RuntimeConfig, opts ...options.Option) error {
	switch cfg.Server {
	case shared.HttpServer:
		h := shared.NewHttpClaimsHandler[T]()
		oidcHandler := oidchttp.New[T](h, opts...)

		return shared.RunHttp(oidcHandler, cfg.Address, cfg.Port)
	case shared.GinServer:
		oidcHandler := oidcgin.New[T](opts...)

		return shared.RunGin[T](oidcHandler, cfg.Address, cfg.Port)
	case shared.EchoJwtServer:
		parseToken := oidcechojwt.New[T](opts...)

		return shared.RunEchoJWT[T](parseToken, cfg.Address, cfg.Port)
	case shared.FiberServer:
		oidcHandler := oidcfiber.New[T](opts...)

		return shared.RunFiber[T](oidcHandler, cfg.Address, cfg.Port)
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
