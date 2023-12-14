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


## Testing

`make test`


## Notes on admin JWT/access

1. Build the project + jwt-util, `make build`

2. To generate a new RSA keypair: `./bin/jwt-util` and copy the private/public pairs and
update waas-auth.conf `[admin] public_key = ".."` value. Note the JWT token generated for you as well.
In the future, we should enhance this CLI tool.

