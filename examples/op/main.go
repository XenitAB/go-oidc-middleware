package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/xenitab/go-oidc-middleware/optest"
)

func main() {
	op, err := optest.New(
		optest.WithIssuer("http://localhost:8082"),
		optest.WithoutAutoStart(),
		optest.WithDefaultTestUser("test"),
		optest.WithTestUsers(map[string]optest.TestUser{
			"test": {
				Audience:           "https://localhost:8081",
				Subject:            "test",
				Name:               "Kalle Kula",
				GivenName:          "Kalle",
				FamilyName:         "Kula",
				Locale:             "sv-SE",
				Email:              "foo@bar.net",
				AccessTokenKeyType: "at+jwt",
				IdTokenKeyType:     "jwt",
				ExtraIdTokenClaims: map[string]interface{}{
					"client_id": "pkce-cli",
				},
				ExtraAccessTokenClaims: map[string]interface{}{
					"client_id": "pkce-cli",
				},
			},
		}),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to load op default: %v\n", err)
		os.Exit(1)
	}

	r := gin.Default()
	opRouter := op.GetRouter()

	r.Any("/.well-known/openid-configuration", gin.WrapH(opRouter))
	r.Any("/authorization", gin.WrapH(opRouter))
	r.Any("/token", gin.WrapH(opRouter))
	r.Any("/jwks", gin.WrapH(opRouter))

	r.GET("/get_test_token", func(c *gin.Context) {
		token, err := op.GetToken()
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		c.String(200, token.AccessToken)
	})

	r.Run(":8082")
}
