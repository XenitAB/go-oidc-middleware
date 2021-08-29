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

func run(runtimeCfg shared.RuntimeConfig) error {
	var opts []options.Option

	switch runtimeCfg.Provider {
	case shared.Auth0Provider:
		cfg, err := shared.NewAuth0Config()
		if err != nil {
			return err
		}

		opts = []options.Option{
			options.WithIssuer(cfg.Issuer),
			options.WithRequiredTokenType("JWT"),
			options.WithRequiredAudience(cfg.Audience),
			options.WithFallbackSignatureAlgorithm(cfg.FallbackSignatureAlgorithm),
			options.WithRequiredClaims(map[string]interface{}{
				"azp": cfg.ClientID,
			}),
		}
	case shared.AzureADProvider:
		cfg, err := shared.NewAzureADConfig()
		if err != nil {
			return err
		}

		opts = []options.Option{
			options.WithIssuer(cfg.Issuer),
			options.WithRequiredTokenType("JWT"),
			options.WithRequiredAudience(cfg.Audience),
			options.WithFallbackSignatureAlgorithm(cfg.FallbackSignatureAlgorithm),
			options.WithRequiredClaims(map[string]interface{}{
				"tid": cfg.TenantID,
			}),
		}
	case shared.CognitoProvider:
		cfg, err := shared.NewCognitoConfig()
		if err != nil {
			return err
		}
		opts = []options.Option{
			options.WithIssuer(cfg.Issuer),
			options.WithFallbackSignatureAlgorithm(cfg.FallbackSignatureAlgorithm),
			options.WithRequiredClaims(map[string]interface{}{
				"client_id": cfg.ClientID,
			}),
		}
	case shared.OktaProvider:
		cfg, err := shared.NewOktaConfig()
		if err != nil {
			return err
		}
		opts = []options.Option{
			options.WithIssuer(cfg.Issuer),
			options.WithFallbackSignatureAlgorithm(cfg.FallbackSignatureAlgorithm),
			options.WithRequiredClaims(map[string]interface{}{
				"cid": cfg.ClientID,
			}),
		}
	default:
		return fmt.Errorf("unknown provider: %s", runtimeCfg.Provider)
	}

	switch runtimeCfg.Server {
	case shared.HttpServer:
		h := shared.NewHttpClaimsHandler()
		oidcHandler := oidchttp.New(h, opts...)

		return shared.RunHttp(oidcHandler, runtimeCfg.Address, runtimeCfg.Port)
	case shared.GinServer:
		oidcHandler := oidcgin.New(opts...)

		return shared.RunGin(oidcHandler, runtimeCfg.Address, runtimeCfg.Port)
	case shared.EchoJwtServer:
		parseToken := oidcechojwt.New(opts...)

		return shared.RunEchoJWT(parseToken, runtimeCfg.Address, runtimeCfg.Port)
	case shared.FiberServer:
		oidcHandler := oidcfiber.New(opts...)

		return shared.RunFiber(oidcHandler, runtimeCfg.Address, runtimeCfg.Port)
	default:
		return fmt.Errorf("unknown server: %s", runtimeCfg.Server)
	}
}
