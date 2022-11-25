package optest

import (
	"crypto/rand"
	"encoding/base64"
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

func (op *OPTest) newAccessToken(id string, user TestUser, nonce string, now time.Time) (string, error) {
	privKey := op.jwks.getPrivateKey()

	c := map[string]interface{}{
		jwt.IssuerKey:     op.options.Issuer,
		jwt.AudienceKey:   user.Audience,
		jwt.SubjectKey:    user.Subject,
		jwt.ExpirationKey: now.Add(op.options.TokenExpiration).Unix(),
		jwt.NotBeforeKey:  now.Unix(),
		jwt.IssuedAtKey:   now.Unix(),
		"id":              id,
	}

	if nonce != "" {
		c["nonce"] = nonce
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
		"jwt_typ":    "access_token",
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

func (op *OPTest) newIdToken(id string, user TestUser, nonce string, now time.Time) (string, error) {
	privKey := op.jwks.getPrivateKey()
	c := map[string]interface{}{
		jwt.IssuerKey:     op.options.Issuer,
		jwt.AudienceKey:   user.Audience,
		jwt.SubjectKey:    user.Subject,
		jwt.ExpirationKey: now.Add(op.options.TokenExpiration).Unix(),
		jwt.NotBeforeKey:  now.Unix(),
		jwt.IssuedAtKey:   now.Unix(),
		"name":            user.Name,
		"given_name":      user.GivenName,
		"family_name":     user.FamilyName,
		"locale":          user.Locale,
		"email":           user.Email,
		"id":              id,
	}

	if nonce != "" {
		c["nonce"] = nonce
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
		"jwt_typ":    "id_token",
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

func (op *OPTest) newOpaqueAccessToken(id string, user TestUser, nonce string) (string, error) {
	opaqueTokenBytes := make([]byte, 64)
	_, err := rand.Read(opaqueTokenBytes)
	if err != nil {
		return "", err
	}

	opaqueTokenB64 := base64.RawURLEncoding.EncodeToString(opaqueTokenBytes)

	jwtAccessToken, err := op.newAccessToken(id, user, nonce, time.Now())
	if err != nil {
		return "", err
	}

	parsedJwtAccessToken, err := jwt.ParseString(jwtAccessToken)
	if err != nil {
		return "", err
	}

	op.opaqueTokens.set(opaqueTokenB64, jwtAccessToken, parsedJwtAccessToken.Expiration())

	return opaqueTokenB64, nil
}
