# OPTest example

The OPTest provider is just a small wrapper on top of the optest package in go-oidc-middleware.

## Start OPTest

```shell
go run ./op/main.go
```

## Run web server

```shell
TOKEN_ISSUER="http://localhost:8082"
TOKEN_AUDIENCE="https://localhost:8081"
CLIENT_ID="pkce-cli"
go run ./api/main.go --server [server] --provider optest --token-issuer ${TOKEN_ISSUER} --token-audience ${TOKEN_AUDIENCE} --required-optest-client-id ${CLIENT_ID} --port 8081
```

## Test with curl

```shell
ACCESS_TOKEN=$(go run ./pkce-cli/main.go --issuer ${TOKEN_ISSUER} --client-id ${CLIENT_ID} | jq -r ".access_token")
curl -s http://localhost:8081 | jq
curl -s -H "Authorization: Bearer ${ACCESS_TOKEN}" http://localhost:8081 | jq
```
