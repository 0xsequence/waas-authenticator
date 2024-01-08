# waas-authenticator

## Quick usage

1. Copy the sample config file:

```
cp ./etc/waas-auth.sample.conf ./etc/waas-auth.conf
```

2. Run the services (which run in docker):

```
make up
```

Service is now running on http://0.0.0.0:9123/

You can use admin jwt token: `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJoZWxsbyI6IndvcmxkIn0.etvI60-iOY2f9a3d1SBYmbrDllxcYm0rF8tB5YyUWwFMBSArAFG8a6ms1k3OtR9xe8uLTeeOC80eLOMWSUgQd_TZmu5RPNBYMMhcqWnl5H64chO2sFrRDdxUCnNYRccEnDesQACmqaf1bbDCFs8Hwh2O4_rHoscuJ7kb3XBCC2a52Dyh8EYTEXg8DJGmUFQX5XKKb35uurejcKo_5yK2onr26SVm_arl4CCcDeNITv1mP1aGvroj1PUVGTpnd9mScPAoecmihdiMMF9VdXU3KGNvK-l44Miq9-a9mnwOwZNtoxqQxlh-cmcNAV5cGh66zfbPnWKb9t9YrMY4wKtshg`

Note, this token is based on the `[admin] public_key = ".."` public RSA key in PEM format. See below for more details.

ie.

```
curl -H "Content-type: application/json" -H"Authorization: BEARER eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJoZWxsbyI6IndvcmxkIn0.etvI60-iOY2f9a3d1SBYmbrDllxcYm0rF8tB5YyUWwFMBSArAFG8a6ms1k3OtR9xe8uLTeeOC80eLOMWSUgQd_TZmu5RPNBYMMhcqWnl5H64chO2sFrRDdxUCnNYRccEnDesQACmqaf1bbDCFs8Hwh2O4_rHoscuJ7kb3XBCC2a52Dyh8EYTEXg8DJGmUFQX5XKKb35uurejcKo_5yK2onr26SVm_arl4CCcDeNITv1mP1aGvroj1PUVGTpnd9mScPAoecmihdiMMF9VdXU3KGNvK-l44Miq9-a9mnwOwZNtoxqQxlh-cmcNAV5cGh66zfbPnWKb9t9YrMY4wKtshg" http://0.0.0.0:9123/rpc/WaasAuthenticatorAdmin/RuntimeStatus -X POST -d '{}'
```

## Full local stack

The following sample setup should work by default. You may need to change some of the values (especially JWTs) if going for an advanced scenario.

1. Run the following services:

- test chain
- stack `guard_2`
- stack `api`
- this service and localstack (see "Quick usage" section above)

2. Create WaaS API partner:

```
curl -X POST http://localhost:4422/rpc/Wallet/CreatePartner -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJvZ24iOiJodHRwczovL3NlcXVlbmNlLmFwcCIsInNlcnZpY2UiOiJ0ZXN0In0.gy1Pkgua0sq1pz5fao8ksG3rwYlZqnZIhmJ1YolmmY0' -H 'Content-Type: application/json' --data '{"config": {"partnerRecoveryAddress": "0x389f7Cd7FeB76a487d981B53d888E8E69Ed0Fdf1","partnerTrustAddress": "0x389f7Cd7FeB76a487d981B53d888E8E69Ed0Fdf1","userMapRules": {"allowIdTokens": true,"idTokenTemplate": "999008#${.iss}#${.sub}","idTokenTrustedAuthenticatorIssuer": "https://cognito-idp.us-east-2.amazonaws.com/us-east-2_80NdmN8Ru"}},"jwtAlg": "HS256","jwtSecret": "changemenow","name": "TestPartner","projectId": 999008}'
```

3. Create Authenticator tenant:

```
curl -X POST http://localhost:9123/rpc/WaasAuthenticatorAdmin/CreateTenant -H 'Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJoZWxsbyI6IndvcmxkIn0.etvI60-iOY2f9a3d1SBYmbrDllxcYm0rF8tB5YyUWwFMBSArAFG8a6ms1k3OtR9xe8uLTeeOC80eLOMWSUgQd_TZmu5RPNBYMMhcqWnl5H64chO2sFrRDdxUCnNYRccEnDesQACmqaf1bbDCFs8Hwh2O4_rHoscuJ7kb3XBCC2a52Dyh8EYTEXg8DJGmUFQX5XKKb35uurejcKo_5yK2onr26SVm_arl4CCcDeNITv1mP1aGvroj1PUVGTpnd9mScPAoecmihdiMMF9VdXU3KGNvK-l44Miq9-a9mnwOwZNtoxqQxlh-cmcNAV5cGh66zfbPnWKb9t9YrMY4wKtshg' -H 'Content-Type: application/json' --data '{"oidcProviders": [{"aud": "970987756660-35a6tc48hvi8cev9cnknp0iugv9poa23.apps.googleusercontent.com","iss": "https://accounts.google.com"},{"aud": "vb0deun4s6on4388qb7hjsi8p","iss": "https://cognito-idp.us-east-2.amazonaws.com/us-east-2_BSCIWXS6e"}],"projectId": 999008,"waasAccessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJwYXJ0bmVyX2lkIjo5OTkwMDgsInByb2plY3RfaWQiOjk5OTAwOH0.BKej9yAJI64nIc6V3w1fwEyVxkfTFYpRLc1LZBFWcLk"}'
```

4. Update the demo-waas-auth .env file to include the following:

```
VITE_GOOGLE_CLIENT_ID=970987756660-35a6tc48hvi8cev9cnknp0iugv9poa23.apps.googleusercontent.com
VITE_SEQUENCE_API_KEY=eyJzZWNyZXQiOiJUQkQiLCJ0ZW5hbnQiOjk5OTAwOCwiaWRlbnRpdHlQb29sSWQiOiJ1cy1lYXN0LTI6NWY0ZTYxMTgtMGEwMS00M2E3LTliNjItMWUwMWNlODQ1NWIyIiwiZW1haWxDbGllbnRJZCI6InN1bXNzOGdjdWE0aTNmcjZkOXBkM2oxa28iLCJpZHBSZWdpb24iOiJ1cy1lYXN0LTIiLCJycGNTZXJ2ZXIiOiJodHRwOi8vbG9jYWxob3N0OjkxMjMiLCJrbXNSZWdpb24iOiJ1cy1lYXN0LTEiLCJlbWFpbFJlZ2lvbiI6InVzLWVhc3QtMiIsImtleUlkIjoiYXJuOmF3czprbXM6dXMtZWFzdC0xOjAwMDAwMDAwMDAwMDprZXkvYWViOTllMGYtOWU4OS00NGRlLWEwODQtZTE4MTdhZjQ3Nzc4IiwiZW5kcG9pbnQiOiJodHRwOi8vbG9jYWxob3N0OjQ1NjYifQ==
```

5. Run the demo-waas-auth.


## Testing

`make test`


## Notes on admin JWT/access

1. Build the project + jwt-util, `make build`

2. To generate a new RSA keypair: `./bin/jwt-util` and copy the private/public pairs and
update waas-auth.conf `[admin] public_key = ".."` value. Note the JWT token generated for you as well.
In the future, we should enhance this CLI tool.

