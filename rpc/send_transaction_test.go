package rpc_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/0xsequence/ethkit/ethwallet"
	"github.com/0xsequence/go-sequence/intents"
	"github.com/0xsequence/waas-authenticator/proto"
	"github.com/0xsequence/waas-authenticator/rpc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRPC_SendIntent_SendTransaction(t *testing.T) {
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

	require.NoError(t, svc.Tenants.Add(ctx, tenant))
	require.NoError(t, svc.Accounts.Put(ctx, acc))
	require.NoError(t, svc.Sessions.Put(ctx, sess))

	walletAddr, err := rpc.AddressForUser(context.Background(), tntData, acc.UserID)
	require.NoError(t, err)

	srv := httptest.NewServer(svc.Handler())
	defer srv.Close()

	intentData := &intents.IntentDataSendTransaction{
		Identifier: "identifier",
		Wallet:     walletAddr,
		Network:    "1",
		Transactions: []json.RawMessage{
			json.RawMessage(`{"data":"0x010203","to":"0x27CabC9700EE6Db2797b6AC1e1eCe81C72A2cD8D","type":"transaction","value":"0x2000000000"}`),
		},
	}
	intent := generateSignedIntent(t, intents.IntentName_sendTransaction, intentData, signingSession)

	c := proto.NewWaasAuthenticatorClient(srv.URL, http.DefaultClient)
	header := make(http.Header)
	header.Set("X-Sequence-Project", strconv.Itoa(int(tenant.ProjectID)))
	ctx, err = proto.WithHTTPRequestHeaders(ctx, header)
	require.NoError(t, err)

	res, err := c.SendIntent(ctx, intent)
	require.NoError(t, err)
	assert.Equal(t, proto.IntentResponseCode_transactionReceipt, res.Code)
	assert.NotEmpty(t, res.Data)
}
