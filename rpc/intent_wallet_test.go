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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRPC_SendIntent_RejectsOtherUsersWallet(t *testing.T) {
	ctx := context.Background()

	issuer, _, closeJWKS := issueAccessTokenAndRunJwksServer(t)
	defer closeJWKS()

	svc := initRPC(t)
	tenant, tntData := newTenant(t, svc.Enclave, issuer)
	require.NoError(t, svc.Tenants.Add(ctx, tenant))

	newUser := func() (intents.Session, string) {
		sessWallet, err := ethwallet.NewWalletFromRandomEntropy()
		require.NoError(t, err)
		signingSession := intents.NewSessionP256K1(sessWallet)

		acc := newAccount(t, tenant, svc.Enclave, newOIDCIdentity(issuer), sessWallet)
		sess := newSession(t, tenant, svc.Enclave, issuer, signingSession)
		require.NoError(t, svc.Accounts.Put(ctx, acc))
		require.NoError(t, svc.Sessions.Put(ctx, sess))

		walletAddr, err := rpc.AddressForUser(ctx, tntData, acc.UserID)
		require.NoError(t, err)
		return signingSession, walletAddr
	}
	attacker, _ := newUser()
	_, victimWallet := newUser()

	srv := httptest.NewServer(svc.Handler())
	defer srv.Close()

	c := proto.NewWaasAuthenticatorClient(srv.URL, http.DefaultClient)
	header := make(http.Header)
	header.Set("X-Sequence-Project", strconv.Itoa(int(tenant.ProjectID)))
	ctx, err := proto.WithHTTPRequestHeaders(ctx, header)
	require.NoError(t, err)

	cases := map[intents.IntentName]any{
		intents.IntentName_signMessage: &intents.IntentDataSignMessage{
			Network: "1",
			Wallet:  victimWallet,
			Message: "Test",
		},
		intents.IntentName_adoptChildWallet: &intents.IntentDataAdoptChildWallet{
			Network: "1",
			Wallet:  victimWallet,
			Adopter: "0x6Db96732D4F0F4D4817d51C10Fe861c40Dc045ed",
		},
		intents.IntentName_getAdopter: &intents.IntentDataGetAdopter{
			Wallet: victimWallet,
		},
	}
	for name, data := range cases {
		t.Run(string(name), func(t *testing.T) {
			intent := generateSignedIntent(t, name, data, attacker)
			_, err := c.SendIntent(ctx, intent)
			require.Error(t, err)
			assert.ErrorIs(t, err, proto.ErrUnauthorized)
		})
	}
}

func TestRPC_SendIntent_AdoptChildWalletDisabled(t *testing.T) {
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

	walletAddr, err := rpc.AddressForUser(ctx, tntData, acc.UserID)
	require.NoError(t, err)

	srv := httptest.NewServer(svc.Handler())
	defer srv.Close()

	c := proto.NewWaasAuthenticatorClient(srv.URL, http.DefaultClient)
	header := make(http.Header)
	header.Set("X-Sequence-Project", strconv.Itoa(int(tenant.ProjectID)))
	ctx, err = proto.WithHTTPRequestHeaders(ctx, header)
	require.NoError(t, err)

	// Even for the caller's own wallet: the feature had no legitimate use.
	intent := generateSignedIntent(t, intents.IntentName_adoptChildWallet, &intents.IntentDataAdoptChildWallet{
		Network: "1",
		Wallet:  walletAddr,
		Adopter: "0x6Db96732D4F0F4D4817d51C10Fe861c40Dc045ed",
	}, signingSession)
	_, err = c.SendIntent(ctx, intent)
	require.Error(t, err)
	assert.ErrorIs(t, err, proto.ErrUnauthorized)
}
