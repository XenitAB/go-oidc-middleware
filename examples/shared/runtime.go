package shared

import (
	"fmt"

	"github.com/cristalhq/aconfig"
)

type Server string

const (
	HttpServer    Server = "http"
	GinServer     Server = "gin"
	EchoJwtServer Server = "echojwt"
	FiberServer   Server = "fiber"
)

func (s Server) Validate() error {
	switch s {
	case HttpServer, GinServer, EchoJwtServer, FiberServer:
		return nil
	default:
		return fmt.Errorf("not a supported server (%s), use one of: http, gin, echojwt, fiber", s)
	}
}

type Provider string

const (
	Auth0Provider   Provider = "auth0"
	AzureADProvider Provider = "azuread"
	CognitoProvider Provider = "cognito"
	OktaProvider    Provider = "okta"
)

func (p Provider) Validate() error {
	switch p {
	case Auth0Provider, AzureADProvider, CognitoProvider, OktaProvider:
		return nil
	default:
		return fmt.Errorf("not a supported provider (%s), use one of: auth0, azuread, cognito, okta", p)
	}
}

type RuntimeConfig struct {
	Server                     Server            `flag:"server" env:"server" usage:"what server to use" required:"true"`
	Provider                   Provider          `flag:"provider" env:"PROVIDER" usage:"what provider to use" required:"true"`
	Address                    string            `flag:"address" env:"ADDRESS" default:"127.0.0.1" usage:"address webserver will listen to"`
	Port                       int               `flag:"port" env:"PORT" default:"8080" usage:"port webserver will listen to"`
	Issuer                     string            `flag:"token-issuer" env:"TOKEN_ISSUER" usage:"the oidc issuer url for tokens"`
	Audience                   string            `flag:"token-audience" env:"TOKEN_AUDIENCE" usage:"the audience that tokens need to contain"`
	ClientID                   string            `flag:"client-id" env:"CLIENT_ID" usage:"the client id that tokens need to contain"`
	FallbackSignatureAlgorithm string            `flag:"fallback-signature-algorithm" env:"FALLBACK_SIGNATURE_ALGORITHM" default:"RS256" usage:"if the issue jwks doesn't contain key alg, use the following signature algorithm to verify the signature of the tokens"`
	RequiredClaims             map[string]string `flag:"required-claims" env:"REQUIRED_CLAIMS" usage:"adds required claims"`
}

func NewRuntimeConfig() (RuntimeConfig, error) {
	var cfg RuntimeConfig

	loader := aconfig.LoaderFor(&cfg, aconfig.Config{
		SkipDefaults:      false,
		SkipFiles:         true,
		SkipEnv:           false,
		SkipFlags:         false,
		AllowUnknownFlags: true,
		EnvPrefix:         "",
		FlagPrefix:        "",
		Files:             []string{},
		FileDecoders:      map[string]aconfig.FileDecoder{},
	})

	if err := loader.Load(); err != nil {
		return RuntimeConfig{}, err
	}

	if err := cfg.Server.Validate(); err != nil {
		return RuntimeConfig{}, err
	}

	if err := cfg.Provider.Validate(); err != nil {
		return RuntimeConfig{}, err
	}

	return cfg, nil
}
