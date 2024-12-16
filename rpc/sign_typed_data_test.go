package rpc_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/0xsequence/ethkit/ethcoder"
	"github.com/0xsequence/ethkit/ethwallet"
	"github.com/0xsequence/go-sequence/intents"
	"github.com/0xsequence/waas-authenticator/proto"
	"github.com/0xsequence/waas-authenticator/rpc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRPC_SendIntent_SignTypedData(t *testing.T) {
	ctx := context.Background()

	issuer, _, closeJWKS := issueAccessTokenAndRunJwksServer(t)
	defer closeJWKS()

	sessWallet, err := ethwallet.NewWalletFromRandomEntropy()
	require.NoError(t, err)
	signingSession := intents.NewSessionP256K1(sessWallet)

	svc := initRPC(t)

	tenant, tntData := newTenant(t, svc.Enclave, issuer)
	acc := newAccount(t, tenant, svc.Enclave, newOIDCIdentity(issuer), sessWallet)
	sess := newSession(t, tenant, svc.Enclave, issuer, signingSession)

	walletAddr, err := rpc.AddressForUser(context.Background(), tntData, acc.UserID)
	require.NoError(t, err)

	require.NoError(t, svc.Tenants.Add(ctx, tenant))
	require.NoError(t, svc.Accounts.Put(ctx, acc))
	require.NoError(t, svc.Sessions.Put(ctx, sess))

	srv := httptest.NewServer(svc.Handler())
	defer srv.Close()

	intentData := &intents.IntentDataSignTypedData{
		Network: "1",
		Wallet:  walletAddr,
		TypedData: &ethcoder.TypedData{
			Types: ethcoder.TypedDataTypes{
				"EIP712Domain": []ethcoder.TypedDataArgument{
					{Name: "name", Type: "string"},
				},
				"Person": []ethcoder.TypedDataArgument{
					{Name: "name", Type: "string"},
					{Name: "wallet", Type: "address"},
					{Name: "age", Type: "uint8"},
				},
			},
			PrimaryType: "Person",
			Domain: ethcoder.TypedDataDomain{
				Name: "DomainName",
			},
			Message: map[string]interface{}{
				"name":   "John Doe",
				"wallet": walletAddr,
				"age":    30,
			},
		},
	}
	intent := generateSignedIntent(t, intents.IntentName_signTypedData, intentData, signingSession)

	c := proto.NewWaasAuthenticatorClient(srv.URL, http.DefaultClient)
	header := make(http.Header)
	header.Set("X-Sequence-Project", strconv.Itoa(int(tenant.ProjectID)))
	ctx, err = proto.WithHTTPRequestHeaders(ctx, header)
	require.NoError(t, err)

	res, err := c.SendIntent(ctx, intent)
	require.NoError(t, err)
	assert.Equal(t, proto.IntentResponseCode_signedTypedData, res.Code)
	assert.NotEmpty(t, res.Data)
}
