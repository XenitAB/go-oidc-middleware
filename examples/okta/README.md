# Okta example

Create an Okta organization and a native app. Copy the issuer and client id.

## Run web server

### Echo JWT

```shell
TOKEN_ISSUER="https://<domain>.okta.com/oauth2/default"
CLIENT_ID="OktaClientID"
go run ./okta/echojwt/main.go --token-issuer ${TOKEN_ISSUER} --client-id ${CLIENT_ID} --port 8081
```

### net/http & mux

```shell
TOKEN_ISSUER="https://<domain>.okta.com/oauth2/default"
CLIENT_ID="OktaClientID"
go run ./okta/http/main.go --token-issuer ${TOKEN_ISSUER} --client-id ${CLIENT_ID} --port 8081
```

### gin

```shell
TOKEN_ISSUER="https://<domain>.okta.com/oauth2/default"
CLIENT_ID="OktaClientID"
go run ./okta/gin/main.go --token-issuer ${TOKEN_ISSUER} --client-id ${CLIENT_ID} --port 8081
```

## Test with curl

```shell
ACCESS_TOKEN=$(go run ./pkce-cli/main.go --issuer ${TOKEN_ISSUER} --client-id ${CLIENT_ID} | jq -r ".access_token")
curl -s http://localhost:8081 | jq
curl -s -H "Authorization: Bearer ${ACCESS_TOKEN}" http://localhost:8081 | jq
```