package rpc_test

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	mathrand "math/rand"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/0xsequence/ethkit/ethwallet"
	"github.com/0xsequence/ethkit/go-ethereum/common/hexutil"
	"github.com/0xsequence/nitrocontrol/aescbc"
	"github.com/0xsequence/nitrocontrol/enclave"
	"github.com/0xsequence/waas-authenticator/data"
	"github.com/0xsequence/waas-authenticator/proto"
	"github.com/0xsequence/waas-authenticator/rpc"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRPC_RegisterSession(t *testing.T) {
	block, _ := pem.Decode([]byte(testPrivateKey))
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	require.NoError(t, err)

	cfg := initConfig(t)

	issuer, tok, closeJWKS := issueAccessTokenAndRunJwksServer(t)
	defer closeJWKS()

	random := mathrand.New(mathrand.NewSource(42))
	kmsClient := &kmsMock{random: random}
	enc, err := enclave.New(context.Background(), enclave.DummyProvider, kmsClient, privKey)
	require.NoError(t, err)

	tenant := newTenant(t, enc, issuer)

	dbClient := &dbMock{
		sessions: map[string]*data.Session{},
		tenants:  map[uint64][]*data.Tenant{tenant.ProjectID: {tenant}},
	}
	svc := &rpc.RPC{
		Config:     cfg,
		HTTPClient: http.DefaultClient,
		Enclave:    enc,
		Wallets:    &walletServiceMock{},
		Tenants:    data.NewTenantTable(dbClient, "Tenants"),
		Sessions:   data.NewSessionTable(dbClient, "Sessions", "UserID-Index"),
	}

	srv := httptest.NewServer(svc.Handler())
	defer srv.Close()

	sessWallet, err := ethwallet.NewWalletFromRandomEntropy()
	require.NoError(t, err)

	payload := &proto.RegisterSessionPayload{
		ProjectID:      tenant.ProjectID,
		IDToken:        tok,
		SessionAddress: sessWallet.Address().String(),
		FriendlyName:   "FriendlyName",
	}
	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	payloadSigBytes, err := sessWallet.SignMessage(payloadBytes)
	require.NoError(t, err)
	payloadSig := hexutil.Encode(payloadSigBytes)

	dkOut, err := kmsClient.GenerateDataKey(context.Background(), &kms.GenerateDataKeyInput{KeyId: aws.String("TransportKey")})
	require.NoError(t, err)
	encryptedPayloadKey := hexutil.Encode(dkOut.CiphertextBlob)

	payloadCiphertextBytes, err := aescbc.Encrypt(rand.Reader, dkOut.Plaintext, payloadBytes)
	require.NoError(t, err)
	payloadCiphertext := hexutil.Encode(payloadCiphertextBytes)

	c := proto.NewWaasAuthenticatorClient(srv.URL, http.DefaultClient)
	header := make(http.Header)
	header.Set("X-Sequence-Tenant", strconv.Itoa(int(tenant.ProjectID)))
	header.Set("Authorization", "Bearer "+tok)
	ctx, err := proto.WithHTTPRequestHeaders(context.Background(), header)
	require.NoError(t, err)

	sess, _, err := c.RegisterSession(ctx, encryptedPayloadKey, payloadCiphertext, payloadSig)
	require.NoError(t, err)
	require.NotNil(t, sess)

	assert.Equal(t, sessWallet.Address().String(), sess.ID)
	assert.Equal(t, fmt.Sprintf("%d#%s#%s", tenant.ProjectID, issuer, "subject"), sess.UserID)
	assert.Equal(t, "FriendlyName", sess.FriendlyName)
}
