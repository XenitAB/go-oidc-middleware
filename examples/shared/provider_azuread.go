package shared

import "github.com/cristalhq/aconfig"

type AzureADConfig struct {
	Address                    string `flag:"address" env:"ADDRESS" default:"127.0.0.1" usage:"address webserver will listen to"`
	Port                       int    `flag:"port" env:"PORT" default:"8080" usage:"port webserver will listen to"`
	Issuer                     string `flag:"token-issuer" env:"TOKEN_ISSUER" usage:"the oidc issuer url for tokens"`
	Audience                   string `flag:"token-audience" env:"TOKEN_AUDIENCE" usage:"the audience that tokens need to contain"`
	TenantID                   string `flag:"token-tenant-id" env:"TOKEN_TENANT_ID" usage:"the tenant id (tid) that tokens need to contain"`
	FallbackSignatureAlgorithm string `flag:"fallback-signature-algorithm" env:"FALLBACK_SIGNATURE_ALGORITHM" default:"RS256" usage:"if the issue jwks doesn't contain key alg, use the following signature algorithm to verify the signature of the tokens"`
}

func NewAzureADConfig() (AzureADConfig, error) {
	var cfg AzureADConfig

	loader := aconfig.LoaderFor(&cfg, aconfig.Config{
		SkipDefaults: false,
		SkipFiles:    true,
		SkipEnv:      false,
		SkipFlags:    false,
		EnvPrefix:    "",
		FlagPrefix:   "",
		Files:        []string{},
		FileDecoders: map[string]aconfig.FileDecoder{},
	})

	err := loader.Load()
	if err != nil {
		return AzureADConfig{}, err
	}

	return cfg, nil
}
