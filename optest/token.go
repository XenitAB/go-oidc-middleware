package optest

import (
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
)

type TestUser struct {
	Audience               string
	Subject                string
	Name                   string
	GivenName              string
	FamilyName             string
	Locale                 string
	Email                  string
	AccessTokenKeyType     string
	IdTokenKeyType         string
	ExtraIdTokenClaims     map[string]interface{}
	ExtraAccessTokenClaims map[string]interface{}
}

func (op *OPTest) newAccessToken(user TestUser) (string, error) {
	privKey := op.jwks.getPrivateKey()

	c := map[string]interface{}{
		jwt.IssuerKey:     op.options.Issuer,
		jwt.AudienceKey:   user.Audience,
		jwt.SubjectKey:    user.Subject,
		jwt.ExpirationKey: time.Now().Add(op.options.TokenExpiration).Unix(),
		jwt.NotBeforeKey:  time.Now().Unix(),
	}

	token := jwt.New()
	for k, v := range c {
		err := token.Set(k, v)
		if err != nil {
			return "", err
		}
	}

	for k, v := range user.ExtraAccessTokenClaims {
		err := token.Set(k, v)
		if err != nil {
			return "", err
		}
	}

	h := map[string]interface{}{
		jws.KeyIDKey: privKey.KeyID(),
		jws.TypeKey:  user.AccessTokenKeyType,
	}

	headers := jws.NewHeaders()
	for k, v := range h {
		err := headers.Set(k, v)
		if err != nil {
			return "", err
		}
	}

	signedToken, err := jwt.Sign(token, jwa.ES384, privKey, jwt.WithHeaders(headers))
	if err != nil {
		return "", err
	}

	access := string(signedToken)

	return access, nil
}

func (op *OPTest) newIdToken(user TestUser) (string, error) {
	privKey := op.jwks.getPrivateKey()
	c := map[string]interface{}{
		jwt.IssuerKey:     op.options.Issuer,
		jwt.AudienceKey:   user.Audience,
		jwt.SubjectKey:    user.Subject,
		jwt.ExpirationKey: time.Now().Add(op.options.TokenExpiration).Unix(),
		jwt.NotBeforeKey:  time.Now().Unix(),
		"name":            user.Name,
		"given_name":      user.GivenName,
		"family_name":     user.FamilyName,
		"locale":          user.Locale,
		"email":           user.Email,
	}

	token := jwt.New()
	for k, v := range c {
		err := token.Set(k, v)
		if err != nil {
			return "", err
		}
	}

	for k, v := range user.ExtraIdTokenClaims {
		err := token.Set(k, v)
		if err != nil {
			return "", err
		}
	}

	h := map[string]interface{}{
		jws.KeyIDKey: privKey.KeyID(),
		jws.TypeKey:  user.IdTokenKeyType,
	}

	headers := jws.NewHeaders()
	for k, v := range h {
		err := headers.Set(k, v)
		if err != nil {
			return "", err
		}
	}

	signedToken, err := jwt.Sign(token, jwa.ES384, privKey, jwt.WithHeaders(headers))
	if err != nil {
		return "", err
	}

	return string(signedToken), nil
}
