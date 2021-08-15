# Cognito example

Create a Cognito user pool, app client and configure the callback for the app client.

## Run web server

### Echo JWT

```shell
TOKEN_ISSUER="https://cognito-idp.{region}.amazonaws.com/{userPoolId}"
CLIENT_ID="CognitoClientID"
go run ./cognito/echojwt/main.go --token-issuer ${TOKEN_ISSUER} --client-id ${CLIENT_ID} --port 8081
```

### net/http & mux

```shell
TOKEN_ISSUER="https://cognito-idp.{region}.amazonaws.com/{userPoolId}"
CLIENT_ID="CognitoClientID"
go run ./cognito/http/main.go --token-issuer ${TOKEN_ISSUER} --client-id ${CLIENT_ID} --port 8081
```

### gin

```shell
TOKEN_ISSUER="https://cognito-idp.{region}.amazonaws.com/{userPoolId}"
CLIENT_ID="CognitoClientID"
go run ./cognito/gin/main.go --token-issuer ${TOKEN_ISSUER} --client-id ${CLIENT_ID} --port 8081
```

### fiber

```shell
TOKEN_ISSUER="https://cognito-idp.{region}.amazonaws.com/{userPoolId}"
CLIENT_ID="CognitoClientID"
go run ./cognito/fiber/main.go --token-issuer ${TOKEN_ISSUER} --client-id ${CLIENT_ID} --port 8081
```

## Test with curl

```shell
CLIENT_SECRET="CognitoAppSecret"
ACCESS_TOKEN=$(go run ./pkce-cli/main.go --issuer ${TOKEN_ISSUER} --client-id ${CLIENT_ID} --extra-token-params client_secret:${CLIENT_SECRET} | jq -r ".access_token")
curl -s http://localhost:8081 | jq
curl -s -H "Authorization: Bearer ${ACCESS_TOKEN}" http://localhost:8081 | jq
```