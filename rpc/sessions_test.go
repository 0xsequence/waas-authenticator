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
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRPC_RegisterSession(t *testing.T) {
	block, _ := pem.Decode([]byte(testPrivateKey))
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	require.NoError(t, err)

	sessWallet, err := ethwallet.NewWalletFromRandomEntropy()
	require.NoError(t, err)

	type assertionParams struct {
		tenant        *data.Tenant
		issuer        string
		dbClient      *dbMock
		walletService *walletServiceMock
	}
	testCases := map[string]struct {
		assertFn     func(t *testing.T, sess *proto.Session, err error, p assertionParams)
		tokBuilderFn func(b *jwt.Builder)
	}{
		"Basic": {
			assertFn: func(t *testing.T, sess *proto.Session, err error, p assertionParams) {
				require.NoError(t, err)
				require.NotNil(t, sess)

				assert.Equal(t, sessWallet.Address().String(), sess.ID)
				assert.Equal(t, fmt.Sprintf("%d#%s#%s", p.tenant.ProjectID, p.issuer, "subject"), sess.UserID)
				assert.Equal(t, "FriendlyName", sess.FriendlyName)

				assert.Contains(t, p.dbClient.sessions, sess.ID)
				assert.Contains(t, p.walletService.registeredSessions, sess.ID)
			},
		},
		"WithInvalidIssuer": {
			tokBuilderFn: func(b *jwt.Builder) { b.Issuer("https://id.example.com") },
			assertFn: func(t *testing.T, sess *proto.Session, err error, p assertionParams) {
				require.Nil(t, sess)
				require.ErrorContains(t, err, `issuer "https://id.example.com" not valid for this tenant`)
			},
		},
		"WithValidNonce": {
			tokBuilderFn: func(b *jwt.Builder) { b.Claim("nonce", sessWallet.Address().String()) },
			assertFn: func(t *testing.T, sess *proto.Session, err error, p assertionParams) {
				require.NoError(t, err)
				require.NotNil(t, sess)

				assert.Equal(t, sessWallet.Address().String(), sess.ID)
			},
		},
		"WithInvalidNonce": {
			tokBuilderFn: func(b *jwt.Builder) { b.Claim("nonce", "0x1234567890abcdef") },
			assertFn: func(t *testing.T, sess *proto.Session, err error, p assertionParams) {
				require.Nil(t, sess)
				require.ErrorContains(t, err, "JWT validation: nonce not satisfied")
			},
		},
	}

	for label, testCase := range testCases {
		t.Run(label, func(t *testing.T) {
			cfg := initConfig(t)

			issuer, tok, closeJWKS := issueAccessTokenAndRunJwksServer(t, testCase.tokBuilderFn)
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
			walletService := newWalletServiceMock(nil)
			svc := &rpc.RPC{
				Config:     cfg,
				HTTPClient: http.DefaultClient,
				Enclave:    enc,
				Wallets:    walletService,
				Tenants:    data.NewTenantTable(dbClient, "Tenants"),
				Sessions:   data.NewSessionTable(dbClient, "Sessions", "UserID-Index"),
			}

			srv := httptest.NewServer(svc.Handler())
			defer srv.Close()

			intentJSON := fmt.Sprintf(`{"version":"","packet":{"code":"openSession","session":"%s"}}`, sessWallet.Address())
			payload := &proto.RegisterSessionPayload{
				ProjectID:      tenant.ProjectID,
				IDToken:        tok,
				SessionAddress: sessWallet.Address().String(),
				FriendlyName:   "FriendlyName",
				IntentJSON:     intentJSON,
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
			header.Set("X-Access-Key", newRandAccessKey(tenant.ProjectID))
			ctx, err := proto.WithHTTPRequestHeaders(context.Background(), header)
			require.NoError(t, err)

			sess, _, err := c.RegisterSession(ctx, encryptedPayloadKey, payloadCiphertext, payloadSig)
			testCase.assertFn(t, sess, err, assertionParams{
				tenant:        tenant,
				issuer:        issuer,
				dbClient:      dbClient,
				walletService: walletService,
			})
		})
	}
}

func TestRPC_DropSession(t *testing.T) {
	block, _ := pem.Decode([]byte(testPrivateKey))
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	require.NoError(t, err)

	cfg := initConfig(t)

	issuer, _, closeJWKS := issueAccessTokenAndRunJwksServer(t)
	defer closeJWKS()

	random := mathrand.New(mathrand.NewSource(42))
	kmsClient := &kmsMock{random: random}
	enc, err := enclave.New(context.Background(), enclave.DummyProvider, kmsClient, privKey)
	require.NoError(t, err)

	sessWallet, err := ethwallet.NewWalletFromRandomEntropy()
	require.NoError(t, err)

	tenant := newTenant(t, enc, issuer)
	session := newSession(t, enc, issuer, sessWallet)

	dbClient := &dbMock{
		sessions: map[string]*data.Session{session.ID: session},
		tenants:  map[uint64][]*data.Tenant{tenant.ProjectID: {tenant}},
	}
	walletService := newWalletServiceMock([]string{session.ID})
	svc := &rpc.RPC{
		Config:     cfg,
		HTTPClient: http.DefaultClient,
		Enclave:    enc,
		Wallets:    walletService,
		Tenants:    data.NewTenantTable(dbClient, "Tenants"),
		Sessions:   data.NewSessionTable(dbClient, "Sessions", "UserID-Index"),
	}

	srv := httptest.NewServer(svc.Handler())
	defer srv.Close()

	payload := &proto.DropSessionPayload{
		SessionID:     session.ID,
		DropSessionID: session.ID,
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
	header.Set("X-Access-Key", newRandAccessKey(tenant.ProjectID))
	ctx, err := proto.WithHTTPRequestHeaders(context.Background(), header)
	require.NoError(t, err)

	ok, err := c.DropSession(ctx, encryptedPayloadKey, payloadCiphertext, payloadSig)
	require.NoError(t, err)
	require.True(t, ok)

	assert.Empty(t, dbClient.sessions)
	assert.Empty(t, walletService.registeredSessions)
}

func TestRPC_ListSessions(t *testing.T) {
	block, _ := pem.Decode([]byte(testPrivateKey))
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	require.NoError(t, err)

	cfg := initConfig(t)

	issuer, _, closeJWKS := issueAccessTokenAndRunJwksServer(t)
	defer closeJWKS()

	random := mathrand.New(mathrand.NewSource(42))
	kmsClient := &kmsMock{random: random}
	enc, err := enclave.New(context.Background(), enclave.DummyProvider, kmsClient, privKey)
	require.NoError(t, err)

	sessWallet, err := ethwallet.NewWalletFromRandomEntropy()
	require.NoError(t, err)

	tenant := newTenant(t, enc, issuer)
	sess1 := newSession(t, enc, issuer, sessWallet)
	sess2 := newSession(t, enc, issuer, nil)
	sess3 := newSession(t, enc, issuer, nil)

	dbClient := &dbMock{
		sessions: map[string]*data.Session{
			sess1.ID: sess1,
			sess2.ID: sess2,
			sess3.ID: sess3,
		},
		tenants: map[uint64][]*data.Tenant{tenant.ProjectID: {tenant}},
	}
	walletService := newWalletServiceMock([]string{sess1.ID, sess2.ID, sess3.ID})
	svc := &rpc.RPC{
		Config:     cfg,
		HTTPClient: http.DefaultClient,
		Enclave:    enc,
		Wallets:    walletService,
		Tenants:    data.NewTenantTable(dbClient, "Tenants"),
		Sessions:   data.NewSessionTable(dbClient, "Sessions", "UserID-Index"),
	}

	srv := httptest.NewServer(svc.Handler())
	defer srv.Close()

	payload := &proto.ListSessionsPayload{SessionID: sess1.ID}
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
	header.Set("X-Access-Key", newRandAccessKey(tenant.ProjectID))
	ctx, err := proto.WithHTTPRequestHeaders(context.Background(), header)
	require.NoError(t, err)

	sessions, err := c.ListSessions(ctx, encryptedPayloadKey, payloadCiphertext, payloadSig)
	require.NoError(t, err)
	require.Len(t, sessions, 3)
}
