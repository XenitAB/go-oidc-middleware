package shared

import "github.com/cristalhq/aconfig"

type AzureADConfig struct {
	RuntimeConfig
	Issuer                     string `flag:"token-issuer" env:"TOKEN_ISSUER" usage:"the oidc issuer url for tokens"`
	Audience                   string `flag:"token-audience" env:"TOKEN_AUDIENCE" usage:"the audience that tokens need to contain"`
	TenantID                   string `flag:"token-tenant-id" env:"TOKEN_TENANT_ID" usage:"the tenant id (tid) that tokens need to contain"`
	FallbackSignatureAlgorithm string `flag:"fallback-signature-algorithm" env:"FALLBACK_SIGNATURE_ALGORITHM" default:"RS256" usage:"if the issue jwks doesn't contain key alg, use the following signature algorithm to verify the signature of the tokens"`
}

func NewAzureADConfig() (AzureADConfig, error) {
	var cfg AzureADConfig

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
		return AzureADConfig{}, err
	}

	return cfg, nil
}
