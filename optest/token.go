package optest

import (
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
)

func (op *OPTest) newAccessToken() (string, error) {
	privKey := op.jwks.getPrivateKey()

	c := map[string]interface{}{
		jwt.IssuerKey:     op.options.Issuer,
		jwt.AudienceKey:   op.options.Audience,
		jwt.SubjectKey:    op.options.Subject,
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

	for k, v := range op.options.ExtraAccessTokenClaims {
		err := token.Set(k, v)
		if err != nil {
			return "", err
		}
	}

	h := map[string]interface{}{
		jws.KeyIDKey: privKey.KeyID(),
		jws.TypeKey:  op.options.AccessTokenKeyType,
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

func (op *OPTest) newIdToken() (string, error) {
	privKey := op.jwks.getPrivateKey()
	c := map[string]interface{}{
		jwt.IssuerKey:     op.options.Issuer,
		jwt.AudienceKey:   op.options.Audience,
		jwt.SubjectKey:    op.options.Subject,
		jwt.ExpirationKey: time.Now().Add(op.options.TokenExpiration).Unix(),
		jwt.NotBeforeKey:  time.Now().Unix(),
		"name":            op.options.Name,
		"given_name":      op.options.GivenName,
		"family_name":     op.options.FamilyName,
		"locale":          op.options.Locale,
		"email":           op.options.Email,
	}

	token := jwt.New()
	for k, v := range c {
		err := token.Set(k, v)
		if err != nil {
			return "", err
		}
	}

	for k, v := range op.options.ExtraIdTokenClaims {
		err := token.Set(k, v)
		if err != nil {
			return "", err
		}
	}

	h := map[string]interface{}{
		jws.KeyIDKey: privKey.KeyID(),
		jws.TypeKey:  op.options.IdTokenKeyType,
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
