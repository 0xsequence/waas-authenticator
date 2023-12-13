package rpc_test

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	mathrand "math/rand"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/0xsequence/ethkit/ethwallet"
	"github.com/0xsequence/ethkit/go-ethereum/common/hexutil"
	"github.com/0xsequence/nitrocontrol/aescbc"
	"github.com/0xsequence/nitrocontrol/enclave"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/0xsequence/waas-authenticator/config"
	"github.com/0xsequence/waas-authenticator/data"
	"github.com/0xsequence/waas-authenticator/proto"
	"github.com/0xsequence/waas-authenticator/rpc"
)

func TestRPC_GetAddress(t *testing.T) {
	block, _ := pem.Decode([]byte(testPrivateKey))
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	require.NoError(t, err)

	cfg := &config.Config{}

	issuer, tok, closeJWKS := issueAccessTokenAndRunJwksServer(t)
	defer closeJWKS()

	random := mathrand.New(mathrand.NewSource(42))
	kmsClient := &kmsMock{random: random}
	enc, err := enclave.New(context.Background(), enclave.DummyProvider, kmsClient, privKey)
	require.NoError(t, err)

	sessWallet, err := ethwallet.NewWalletFromRandomEntropy()
	require.NoError(t, err)

	tenant := newTenant(t, enc, issuer)
	sess := newSession(t, enc, issuer, sessWallet)

	dbClient := &dbMock{
		sessions: map[string]*data.Session{sess.ID: sess},
		tenants:  map[uint64][]*data.Tenant{tenant.ProjectID: {tenant}},
	}
	svc := &rpc.RPC{
		Config:     cfg,
		HTTPClient: http.DefaultClient,
		Enclave:    enc,
		Tenants:    data.NewTenantTable(dbClient, "Tenants"),
		Sessions:   data.NewSessionTable(dbClient, "Sessions", "UserID-Index"),
	}

	srv := httptest.NewServer(svc.Handler())
	defer srv.Close()

	payload := &proto.GetAddressPayload{SessionID: sess.ID}
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

	addr, err := c.GetAddress(ctx, encryptedPayloadKey, payloadCiphertext, payloadSig)
	require.NoError(t, err)
	assert.NotEmpty(t, addr)
}

func TestRPC_SendIntent_SignMessage(t *testing.T) {
	block, _ := pem.Decode([]byte(testPrivateKey))
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	require.NoError(t, err)

	cfg := &config.Config{}

	issuer, tok, closeJWKS := issueAccessTokenAndRunJwksServer(t)
	defer closeJWKS()

	random := mathrand.New(mathrand.NewSource(42))
	kmsClient := &kmsMock{random: random}
	enc, err := enclave.New(context.Background(), enclave.DummyProvider, kmsClient, privKey)
	require.NoError(t, err)

	sessWallet, err := ethwallet.NewWalletFromRandomEntropy()
	require.NoError(t, err)

	tenant := newTenant(t, enc, issuer)
	sess := newSession(t, enc, issuer, sessWallet)

	dbClient := &dbMock{
		sessions: map[string]*data.Session{sess.ID: sess},
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

	intentJSON := `{"version":"","packet":{"code":"signMessage","message":"Test","network":"1"}}`
	payload := &proto.SendIntentPayload{SessionID: sess.ID, IntentJSON: intentJSON}
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

	resCode, resData, err := c.SendIntent(ctx, encryptedPayloadKey, payloadCiphertext, payloadSig)
	require.NoError(t, err)
	assert.Equal(t, "signedMessage", resCode)
	assert.NotEmpty(t, resData)
}

func TestRPC_SendIntent_SendTransaction(t *testing.T) {
	block, _ := pem.Decode([]byte(testPrivateKey))
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	require.NoError(t, err)

	cfg := &config.Config{}

	issuer, tok, closeJWKS := issueAccessTokenAndRunJwksServer(t)
	defer closeJWKS()

	random := mathrand.New(mathrand.NewSource(42))
	kmsClient := &kmsMock{random: random}
	enc, err := enclave.New(context.Background(), enclave.DummyProvider, kmsClient, privKey)
	require.NoError(t, err)

	sessWallet, err := ethwallet.NewWalletFromRandomEntropy()
	require.NoError(t, err)

	tenant := newTenant(t, enc, issuer)
	sess := newSession(t, enc, issuer, sessWallet)

	dbClient := &dbMock{
		sessions: map[string]*data.Session{sess.ID: sess},
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

	intentJSON := `{"version":"","packet":{"code":"sendTransaction","transactions":[{"data":"0x010203","to":"0x27CabC9700EE6Db2797b6AC1e1eCe81C72A2cD8D","type":"transaction","value":"0x2000000000"}],"network":"1"}}`
	payload := &proto.SendIntentPayload{SessionID: sess.ID, IntentJSON: intentJSON}
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

	resCode, resData, err := c.SendIntent(ctx, encryptedPayloadKey, payloadCiphertext, payloadSig)
	require.NoError(t, err)
	assert.Equal(t, "transactionReceipt", resCode)
	assert.NotEmpty(t, resData)
}
