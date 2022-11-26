package shared

import (
	"fmt"
	"time"

	"github.com/cristalhq/aconfig"
	"github.com/xenitab/go-oidc-middleware/options"
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
	Server                     Server   `flag:"server" env:"server" usage:"what server to use" required:"true"`
	Provider                   Provider `flag:"provider" env:"PROVIDER" usage:"what provider to use" required:"true"`
	Address                    string   `flag:"address" env:"ADDRESS" default:"127.0.0.1" usage:"address webserver will listen to"`
	Port                       int      `flag:"port" env:"PORT" default:"8080" usage:"port webserver will listen to"`
	Issuer                     string   `flag:"token-issuer" env:"TOKEN_ISSUER" usage:"the oidc issuer url for tokens"`
	Audience                   string   `flag:"token-audience" env:"TOKEN_AUDIENCE" usage:"the audience that tokens need to contain"`
	ClientID                   string   `flag:"client-id" env:"CLIENT_ID" usage:"the client id that tokens need to contain"`
	FallbackSignatureAlgorithm string   `flag:"fallback-signature-algorithm" env:"FALLBACK_SIGNATURE_ALGORITHM" default:"RS256" usage:"if the issue jwks doesn't contain key alg, use the following signature algorithm to verify the signature of the tokens"`
	RequiredAuth0ClientId      string   `flag:"required-auth0-client-id" env:"REQUIRED_AUTH0_CLIENT_ID" usage:"the required Auth0 Client ID"`
	RequiredAzureADTenantId    string   `flag:"required-azure-ad-tenant-id" env:"REQUIRED_AZURE_AD_TENANT_ID" usage:"the required Azure AD Tenant ID"`
	RequiredCognitoClientId    string   `flag:"required-cognito-client-id" env:"REQUIRED_COGNITO_CLIENT_ID" usage:"the required Cognito Client ID"`
	RequiredOktaClientId       string   `flag:"required-okta-client-id" env:"REQUIRED_OKTA_CLIENT_ID" usage:"the required Okta Client ID"`
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

type Auth0Claims struct {
	Audience  []string  `json:"aud"`
	ClientId  string    `json:"azp"`
	ExpiresAt time.Time `json:"exp"`
	IssuedAt  time.Time `json:"iat"`
	Issuer    string    `json:"iss"`
	Scope     string    `json:"scope"`
	Subject   string    `json:"sub"`
}

func GetAuth0ClaimsValidationFn(requiredClientId string) options.ClaimsValidationFn[Auth0Claims] {
	return func(claims *Auth0Claims) error {
		if requiredClientId != "" && claims.ClientId != requiredClientId {
			return fmt.Errorf("azp claim is required to be %q but was: %s", requiredClientId, claims.ClientId)
		}

		return nil
	}
}

type AzureADClaims struct {
	Aio               string    `json:"aio"`
	Audience          []string  `json:"aud"`
	Azp               string    `json:"azp"`
	Azpacr            string    `json:"azpacr"`
	ExpiresAt         time.Time `json:"exp"`
	IssuedAt          time.Time `json:"iat"`
	Idp               string    `json:"idp"`
	Issuer            string    `json:"iss"`
	Name              string    `json:"name"`
	NotBefore         time.Time `json:"nbf"`
	Oid               string    `json:"oid"`
	PreferredUsername string    `json:"preferred_username"`
	Rh                string    `json:"rh"`
	Scope             string    `json:"scp"`
	Subject           string    `json:"sub"`
	TenantId          string    `json:"tid"`
	Uti               string    `json:"uti"`
	TokenVersion      string    `json:"ver"`
}

func GetAzureADClaimsValidationFn(requiredTenantId string) options.ClaimsValidationFn[AzureADClaims] {
	return func(claims *AzureADClaims) error {
		if requiredTenantId != "" && claims.TenantId != requiredTenantId {
			return fmt.Errorf("tid claim is required to be %q but was: %s", requiredTenantId, claims.TenantId)
		}

		return nil
	}
}

type CognitoClaims struct {
	AuthTime  int64     `json:"auth_time"`
	ClientId  string    `json:"client_id"`
	EventId   string    `json:"event_id"`
	ExpiresAt time.Time `json:"exp"`
	IssuedAt  time.Time `json:"iat"`
	Issuer    string    `json:"iss"`
	Jti       string    `json:"jti"`
	OriginJti string    `json:"origin_jti"`
	Scope     string    `json:"scope"`
	Subject   string    `json:"sub"`
	TokenUse  string    `json:"token_use"`
	Username  string    `json:"username"`
	Version   int       `json:"version"`
}

func GetCognitoClaimsValidationFn(requiredClientId string) options.ClaimsValidationFn[CognitoClaims] {
	return func(claims *CognitoClaims) error {
		if requiredClientId != "" && claims.ClientId != requiredClientId {
			return fmt.Errorf("client_id claim is required to be %q but was: %s", requiredClientId, claims.ClientId)
		}

		return nil
	}
}

type OktaClaims struct {
	Audience  []string  `json:"aud"`
	AuthTime  int64     `json:"auth_time"`
	ClientId  string    `json:"cid"`
	ExpiresAt time.Time `json:"exp"`
	IssuedAt  time.Time `json:"iat"`
	Issuer    string    `json:"iss"`
	Jti       string    `json:"jti"`
	Scope     []string  `json:"scp"`
	Subject   string    `json:"sub"`
	Uid       string    `json:"uid"`
	Version   int       `json:"ver"`
}

func GetOktaClaimsValidationFn(requiredClientId string) options.ClaimsValidationFn[OktaClaims] {
	return func(claims *OktaClaims) error {
		if requiredClientId != "" && claims.ClientId != requiredClientId {
			return fmt.Errorf("cid claim is required to be %q but was: %s", requiredClientId, claims.ClientId)
		}

		return nil
	}
}
