package optest

import (
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
)

func newAccessToken(issuer string, privKey jwk.Key) (string, error) {
	sid, err := generateRandomString(16)
	if err != nil {
		return "", err
	}

	token := jwt.New()
	if err := token.Set(jwt.IssuerKey, issuer); err != nil {
		return "", err
	}
	if err := token.Set(jwt.AudienceKey, "test-client"); err != nil {
		return "", err
	}
	if err := token.Set(jwt.SubjectKey, "test"); err != nil {
		return "", err
	}
	if err := token.Set(jwt.ExpirationKey, time.Now().Add(3600*time.Second).Unix()); err != nil {
		return "", err
	}
	if err := token.Set(jwt.NotBeforeKey, time.Now().Unix()); err != nil {
		return "", err
	}
	if err := token.Set("sid", sid); err != nil {
		return "", err
	}

	headers := jws.NewHeaders()
	if err := headers.Set(jws.KeyIDKey, privKey.KeyID()); err != nil {
		return "", err
	}
	if err := headers.Set(jws.TypeKey, "JWT+AT"); err != nil {
		return "", err
	}

	signedToken, err := jwt.Sign(token, jwa.ES384, privKey, jwt.WithHeaders(headers))
	if err != nil {
		return "", err
	}

	access := string(signedToken)

	return access, nil
}

func newIdToken(issuer string, privKey jwk.Key) (string, error) {
	token := jwt.New()
	if err := token.Set(jwt.IssuerKey, issuer); err != nil {
		return "", err
	}
	if err := token.Set(jwt.AudienceKey, "test-client"); err != nil {
		return "", err
	}
	if err := token.Set(jwt.SubjectKey, "test"); err != nil {
		return "", err
	}
	if err := token.Set(jwt.ExpirationKey, time.Now().Add(3600*time.Second).Unix()); err != nil {
		return "", err
	}
	if err := token.Set(jwt.NotBeforeKey, time.Now().Unix()); err != nil {
		return "", err
	}

	if err := token.Set("name", "Test Testersson"); err != nil {
		return "", err
	}
	if err := token.Set("given_name", "Test"); err != nil {
		return "", err
	}
	if err := token.Set("family_name", "Testersson"); err != nil {
		return "", err
	}
	if err := token.Set("locale", "en-US"); err != nil {
		return "", err
	}

	if err := token.Set("email", "test@testersson.com"); err != nil {
		return "", err
	}
	if err := token.Set("email_verified", "test@testersson.com"); err != nil {
		return "", err
	}

	headers := jws.NewHeaders()
	if err := headers.Set(jws.KeyIDKey, privKey.KeyID()); err != nil {
		return "", err
	}
	if err := headers.Set(jws.TypeKey, "JWT"); err != nil {
		return "", err
	}

	signedToken, err := jwt.Sign(token, jwa.ES384, privKey, jwt.WithHeaders(headers))
	if err != nil {
		return "", err
	}

	return string(signedToken), nil
}
