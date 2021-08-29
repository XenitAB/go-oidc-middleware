package shared

import "github.com/cristalhq/aconfig"

type Auth0Config struct {
	RuntimeConfig
	Issuer                     string `flag:"token-issuer" env:"TOKEN_ISSUER" usage:"the oidc issuer url for tokens"`
	Audience                   string `flag:"token-audience" env:"TOKEN_AUDIENCE" usage:"the audience that tokens need to contain"`
	ClientID                   string `flag:"client-id" env:"CLIENT_ID" usage:"the client id that tokens need to contain"`
	FallbackSignatureAlgorithm string `flag:"fallback-signature-algorithm" env:"FALLBACK_SIGNATURE_ALGORITHM" default:"RS256" usage:"if the issue jwks doesn't contain key alg, use the following signature algorithm to verify the signature of the tokens"`
}

func NewAuth0Config() (Auth0Config, error) {
	var cfg Auth0Config

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

	err := loader.Load()
	if err != nil {
		return Auth0Config{}, err
	}

	return cfg, nil
}
