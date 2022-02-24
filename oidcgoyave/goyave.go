package oidcgoyave

import (
	"errors"
	"fmt"

	"github.com/xenitab/go-oidc-middleware/internal/oidc"
	"github.com/xenitab/go-oidc-middleware/options"

	"gorm.io/gorm"
	"goyave.dev/goyave/v4"
	"goyave.dev/goyave/v4/auth"
	"goyave.dev/goyave/v4/database"
)

type OIDCAuthenticator struct {
	parseToken oidc.ParseTokenFunc
	opts       *options.Options
	claimName  string
}

var _ auth.Authenticator = (*OIDCAuthenticator)(nil) // implements Authenticator

const (
	// InvalidCredentialsErrorDescription is returned to ErrorHandler if the middleware is unable to find the user in the database
	InvalidCredentialsErrorDescription options.ErrorDescription = "invalid credentials"
)

// New returns an OpenID Connect (OIDC) discovery handler (Authenticator)
// to be used with `goyave`.
func New(claimName string, setters ...options.Option) *OIDCAuthenticator {
	oidcHandler, err := oidc.NewHandler(setters...)
	if err != nil {
		panic(fmt.Sprintf("oidc discovery: %v", err))
	}

	return &OIDCAuthenticator{
		parseToken: oidcHandler.ParseToken,
		opts:       options.New(setters...),
		claimName:  claimName,
	}
}

func onError(errorHandler options.ErrorHandler, description options.ErrorDescription, err error) error {
	if errorHandler != nil {
		errorHandler(description, err)
	}

	return err
}

func (a *OIDCAuthenticator) Authenticate(request *goyave.Request, user interface{}) error {
	ctx := request.Request().Context()

	getHeaderFn := func(key string) string {
		return request.Header().Get(key)
	}

	tokenString, err := oidc.GetTokenString(getHeaderFn, a.opts.TokenString)
	if err != nil {
		return onError(a.opts.ErrorHandler, options.GetTokenErrorDescription, err)
	}

	token, err := a.parseToken(ctx, tokenString)
	if err != nil {
		return onError(a.opts.ErrorHandler, options.ParseTokenErrorDescription, err)
	}

	tokenClaims, err := token.AsMap(ctx)
	if err != nil {
		return onError(a.opts.ErrorHandler, options.ConvertTokenErrorDescription, err)
	}

	request.Extra["jwt_claims"] = tokenClaims
	column := auth.FindColumns(user, "username")[0]
	claimName := a.claimName
	if claimName == "" {
		claimName = "sub"
	}
	result := database.GetConnection().Where(column.Name+" = ?", tokenClaims[claimName]).First(user)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return onError(a.opts.ErrorHandler, InvalidCredentialsErrorDescription, err)
		}
		panic(result.Error)
	}

	return nil
}
