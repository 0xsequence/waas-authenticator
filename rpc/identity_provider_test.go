package rpc_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/0xsequence/ethkit/ethwallet"
	"github.com/0xsequence/go-sequence/intents"
	"github.com/0xsequence/waas-authenticator/proto"
	"github.com/0xsequence/waas-authenticator/rpc"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRPC_SendIntent_GetIdToken(t *testing.T) {
	ctx := context.Background()

	issuer, _, closeJWKS := issueAccessTokenAndRunJwksServer(t, func(b *jwt.Builder, s string) {
		b.Claim("email", "user@example.com").Claim("email_verified", true)
	})
	defer closeJWKS()

	sessWallet, err := ethwallet.NewWalletFromRandomEntropy()
	require.NoError(t, err)
	signingSession := intents.NewSessionP256K1(sessWallet)

	svc := initRPC(t)

	tenant, tntData := newTenant(t, svc.Enclave, withOIDC(issuer))
	acc := newAccount(t, tenant, svc.Enclave, newOIDCIdentity(issuer), sessWallet)
	sess := newSession(t, tenant, svc.Enclave, issuer, signingSession)

	walletAddr, err := rpc.AddressForUser(context.Background(), tntData, acc.UserID)
	require.NoError(t, err)

	require.NoError(t, svc.Tenants.Add(ctx, tenant))
	require.NoError(t, svc.Accounts.Put(ctx, acc))
	require.NoError(t, svc.Sessions.Put(ctx, sess))

	srv := httptest.NewServer(svc.Handler())
	defer srv.Close()
	svc.Config.Signing.Issuer = srv.URL
	svc.Config.Signing.AudiencePrefix = "https://sequence.build/project/"

	intentData := &intents.IntentDataGetIdToken{
		Wallet:    walletAddr,
		SessionID: sess.ID,
		Nonce:     "NONCE",
	}
	intent := generateSignedIntent(t, intents.IntentName_getIdToken, intentData, signingSession)

	c := proto.NewWaasAuthenticatorClient(srv.URL, http.DefaultClient)
	header := make(http.Header)
	header.Set("X-Sequence-Project", strconv.Itoa(int(tenant.ProjectID)))
	ctx, err = proto.WithHTTPRequestHeaders(ctx, header)
	require.NoError(t, err)

	res, err := c.SendIntent(ctx, intent)
	require.NoError(t, err)
	assert.Equal(t, proto.IntentResponseCode_idToken, res.Code)
	assert.NotEmpty(t, res.Data)

	resData := unmarshalResponse[intents.IntentResponseIdToken](t, res.Data)

	jwks, err := jwk.Fetch(context.Background(), srv.URL+"/.well-known/jwks.json")
	require.NoError(t, err)

	opts := []jwt.ParseOption{
		jwt.WithKeySet(jwks),
		jwt.WithIssuer(srv.URL),
		jwt.WithAudience("https://sequence.build/project/" + strconv.Itoa(int(tenant.ProjectID))),
		jwt.WithSubject(walletAddr),
		jwt.WithClaimValue("nonce", "NONCE"),
		jwt.WithClaimValue("email", "user@example.com"),
	}
	tok, err := jwt.Parse([]byte(resData.IdToken), opts...)
	require.NoError(t, err)
	require.NotNil(t, tok)

	identClaim, ok := tok.Get(srv.URL + "/identity")
	require.True(t, ok)
	identMap, ok := identClaim.(map[string]any)
	require.True(t, ok, "should be a map, is %+v", identClaim)
	assert.Equal(t, "OIDC", identMap["type"])
	assert.Equal(t, issuer, identMap["iss"])
	assert.Equal(t, "SUBJECT", identMap["sub"])
}
