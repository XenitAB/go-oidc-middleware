# Go OIDC Middleware examples

## Introduction

To show how to use the middleware, a few examples has been created. If you want to run the examples according to their readmes, run all commands from the `example` directory.

## Tools

### PKCE-CLI

There's a CLI utility that makes it easy to use the different OpenID Providers (authorization servers) and get tokens to test with.

[PKCE-CLI Readme](pkce-cli/README.md)

## Providers

When starting the api for one of the providers, change `[server]` to one of: `http`, `echojwt`, `gin` or `fiber`

### Azure AD

[Azure AD Readme](PROVIDER_AZUREAD.md)

### Okta

[Okta Readme](PROVIDER_OKTA.md)

### Auth0

[Auth0 Readme](PROVIDER_AUTH0.md)

### Cognito

[Cognito Readme](PROVIDER_COGNITO.md)