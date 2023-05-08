package main

import (
	"examples/shared"
	"fmt"
	"os"

	"github.com/xenitab/go-oidc-middleware/oidcecho"
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
			"RequiredAuth0ClientId":      cfg.RequiredAuth0ClientId,
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
		}
		claimsValidationFn := shared.GetAuth0ClaimsValidationFn(cfg.RequiredAuth0ClientId)
		return getHandler(cfg, claimsValidationFn, opts...)
	case shared.AzureADProvider:
		inputs := map[string]string{
			"issuer":                     cfg.Issuer,
			"audience":                   cfg.Audience,
			"fallbackSignatureAlgorithm": cfg.FallbackSignatureAlgorithm,
			"RequiredAzureADTenantId":    cfg.RequiredAzureADTenantId,
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
		}
		claimsValidationFn := shared.GetAzureADClaimsValidationFn(cfg.RequiredAzureADTenantId)
		return getHandler(cfg, claimsValidationFn, opts...)
	case shared.CognitoProvider:
		inputs := map[string]string{
			"issuer":                     cfg.Issuer,
			"fallbackSignatureAlgorithm": cfg.FallbackSignatureAlgorithm,
			"RequiredCognitoClientId":    cfg.RequiredCognitoClientId,
		}

		err := stringNotEmpty(inputs)
		if err != nil {
			return err
		}

		opts = []options.Option{
			options.WithIssuer(cfg.Issuer),
			options.WithFallbackSignatureAlgorithm(cfg.FallbackSignatureAlgorithm),
		}
		claimsValidationFn := shared.GetCognitoClaimsValidationFn(cfg.RequiredCognitoClientId)
		return getHandler(cfg, claimsValidationFn, opts...)
	case shared.OktaProvider:
		inputs := map[string]string{
			"issuer":                     cfg.Issuer,
			"fallbackSignatureAlgorithm": cfg.FallbackSignatureAlgorithm,
			"RequiredOktaClientId":       cfg.RequiredOktaClientId,
		}

		err := stringNotEmpty(inputs)
		if err != nil {
			return err
		}

		opts = []options.Option{
			options.WithIssuer(cfg.Issuer),
			options.WithFallbackSignatureAlgorithm(cfg.FallbackSignatureAlgorithm),
		}
		claimsValidationFn := shared.GetOktaClaimsValidationFn(cfg.RequiredOktaClientId)
		return getHandler(cfg, claimsValidationFn, opts...)
	case shared.OPTestProvider:
		inputs := map[string]string{
			"issuer":                     cfg.Issuer,
			"fallbackSignatureAlgorithm": cfg.FallbackSignatureAlgorithm,
			"RequiredOPTestClientId":     cfg.RequiredOPTestClientId,
		}

		err := stringNotEmpty(inputs)
		if err != nil {
			return err
		}

		opts = []options.Option{
			options.WithIssuer(cfg.Issuer),
			options.WithFallbackSignatureAlgorithm(cfg.FallbackSignatureAlgorithm),
		}
		claimsValidationFn := shared.GetOPTestClaimsValidationFn(cfg.RequiredOPTestClientId)
		return getHandler(cfg, claimsValidationFn, opts...)
	default:
		return fmt.Errorf("unknown provider: %s", cfg.Provider)
	}
}

func getHandler[T any](cfg shared.RuntimeConfig, claimsValidationFn options.ClaimsValidationFn[T], opts ...options.Option) error {
	switch cfg.Server {
	case shared.HttpServer:
		h := shared.NewHttpClaimsHandler[T]()
		oidcHandler := oidchttp.New(h, claimsValidationFn, opts...)

		return shared.RunHttp(oidcHandler, cfg.Address, cfg.Port)
	case shared.GinServer:
		oidcHandler := oidcgin.New(claimsValidationFn, opts...)

		return shared.RunGin[T](oidcHandler, cfg.Address, cfg.Port)
	case shared.EchoServer:
		oidcMiddleware := oidcecho.New(claimsValidationFn, opts...)

		return shared.RunEcho[T](oidcMiddleware, cfg.Address, cfg.Port)
	case shared.FiberServer:
		oidcHandler := oidcfiber.New(claimsValidationFn, opts...)

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
