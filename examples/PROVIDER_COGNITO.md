# Cognito example

Create a Cognito user pool, app client and configure the callback for the app client.

## Run web server

```shell
TOKEN_ISSUER="https://cognito-idp.{region}.amazonaws.com/{userPoolId}"
CLIENT_ID="CognitoClientID"
go run ./api/main.go --server [server] --provider cognito --token-issuer ${TOKEN_ISSUER} --required-claims client_id:${CLIENT_ID} --port 8081
```

## Test with curl

```shell
CLIENT_SECRET="CognitoAppSecret"
ACCESS_TOKEN=$(go run ./pkce-cli/main.go --issuer ${TOKEN_ISSUER} --client-id ${CLIENT_ID} --extra-token-params client_secret:${CLIENT_SECRET} | jq -r ".access_token")
curl -s http://localhost:8081 | jq
curl -s -H "Authorization: Bearer ${ACCESS_TOKEN}" http://localhost:8081 | jq
```