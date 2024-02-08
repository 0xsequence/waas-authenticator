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
	"strings"
	"testing"
	"time"

	"github.com/0xsequence/ethkit/ethwallet"
	"github.com/0xsequence/ethkit/go-ethereum/common/hexutil"
	"github.com/0xsequence/go-sequence/intents/packets"
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
				assert.Equal(t, fmt.Sprintf("%d|%s", p.tenant.ProjectID, strings.ToLower(sess.ID)), sess.UserID)
				assert.Equal(t, "FriendlyName", sess.FriendlyName)

				assert.Contains(t, p.dbClient.sessions, sess.ID)
				assert.Contains(t, p.dbClient.accounts[p.tenant.ProjectID], sess.Identity.String())
				assert.Contains(t, p.walletService.registeredSessions, sess.ID)
				assert.Contains(t, p.walletService.registeredUsers, sess.UserID)
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
		"WithInvalidNonceButValidSessionAddressClaim": {
			tokBuilderFn: func(b *jwt.Builder) {
				b.Claim("nonce", "0x1234567890abcdef").
					Claim("sequence:session_address", sessWallet.Address().String())
			},
			assertFn: func(t *testing.T, sess *proto.Session, err error, p assertionParams) {
				require.NoError(t, err)
				require.NotNil(t, sess)

				assert.Equal(t, sessWallet.Address().String(), sess.ID)
			},
		},
		"WithVerifiedEmail": {
			tokBuilderFn: func(b *jwt.Builder) {
				b.Claim("email", "user@example.com").Claim("email_verified", "true")
			},
			assertFn: func(t *testing.T, sess *proto.Session, err error, p assertionParams) {
				require.NoError(t, err)
				require.NotNil(t, sess)

				assert.Equal(t, "user@example.com", sess.Identity.Email)
			},
		},
		"WithUnverifiedEmail": {
			tokBuilderFn: func(b *jwt.Builder) {
				b.Claim("email", "user@example.com").Claim("email_verified", "false")
			},
			assertFn: func(t *testing.T, sess *proto.Session, err error, p assertionParams) {
				require.NoError(t, err)
				require.NotNil(t, sess)

				assert.Equal(t, "", sess.Identity.Email)
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

			tenant, _ := newTenant(t, enc, issuer)

			dbClient := &dbMock{
				sessions: map[string]*data.Session{},
				tenants:  map[uint64][]*data.Tenant{tenant.ProjectID: {tenant}},
				accounts: map[uint64]map[string]*data.Account{},
			}
			svc := initRPC(cfg, enc, dbClient)
			walletService := newWalletServiceMock(nil)
			svc.Wallets = walletService

			srv := httptest.NewServer(svc.Handler())
			defer srv.Close()

			packet := &packets.OpenSessionPacket{
				BasePacket: packets.BasePacket{
					Code:    packets.OpenSessionPacketCode,
					Issued:  uint64(time.Now().Add(-1 * time.Second).Unix()),
					Expires: uint64(time.Now().Add(5 * time.Minute).Unix()),
				},
				Session: sessWallet.Address().String(),
				Proof:   packets.OpenSessionPacketProof{IDToken: tok},
			}
			intentJSON := generateIntent(t, sessWallet, packet)

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

	tenant, _ := newTenant(t, enc, issuer)
	session := newSession(t, enc, issuer, sessWallet)

	dbClient := &dbMock{
		sessions: map[string]*data.Session{session.ID: session},
		tenants:  map[uint64][]*data.Tenant{tenant.ProjectID: {tenant}},
	}
	svc := initRPC(cfg, enc, dbClient)
	walletService := newWalletServiceMock([]string{session.ID})
	svc.Wallets = walletService

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

	tenant, _ := newTenant(t, enc, issuer)
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
	svc := initRPC(cfg, enc, dbClient)
	svc.Wallets = walletService

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

func TestRPC_GetAddress(t *testing.T) {
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

	tenant, _ := newTenant(t, enc, issuer)
	sess := newSession(t, enc, issuer, sessWallet)

	dbClient := &dbMock{
		sessions: map[string]*data.Session{sess.ID: sess},
		tenants:  map[uint64][]*data.Tenant{tenant.ProjectID: {tenant}},
	}
	svc := initRPC(cfg, enc, dbClient)

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
	header.Set("X-Access-Key", newRandAccessKey(tenant.ProjectID))
	ctx, err := proto.WithHTTPRequestHeaders(context.Background(), header)

	addr, err := c.GetAddress(ctx, encryptedPayloadKey, payloadCiphertext, payloadSig)
	require.NoError(t, err)
	assert.NotEmpty(t, addr)
}

func TestRPC_SendIntent_SignMessage(t *testing.T) {
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

	tenant, tntData := newTenant(t, enc, issuer)
	acc := newAccount(t, enc, issuer, sessWallet)
	sess := newSession(t, enc, issuer, sessWallet)

	walletAddr, err := rpc.AddressForUser(context.Background(), tntData, acc.UserID)
	require.NoError(t, err)

	dbClient := &dbMock{
		sessions: map[string]*data.Session{sess.ID: sess},
		tenants:  map[uint64][]*data.Tenant{tenant.ProjectID: {tenant}},
		accounts: map[uint64]map[string]*data.Account{
			tenant.ProjectID: {acc.UserID: acc},
		},
	}
	svc := initRPC(cfg, enc, dbClient)

	srv := httptest.NewServer(svc.Handler())
	defer srv.Close()

	packet := &packets.SignMessagePacket{
		BasePacketForWallet: packets.BasePacketForWallet{
			BasePacket: packets.BasePacket{
				Code:    packets.SignMessagePacketCode,
				Issued:  uint64(time.Now().Add(-1 * time.Second).Unix()),
				Expires: uint64(time.Now().Add(5 * time.Minute).Unix()),
			},
			Wallet: walletAddr,
		},
		Network: "1",
		Message: "Test",
	}
	intentJSON := generateIntent(t, sessWallet, packet)

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
	header.Set("X-Access-Key", newRandAccessKey(tenant.ProjectID))
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

	cfg := initConfig(t)

	issuer, _, closeJWKS := issueAccessTokenAndRunJwksServer(t)
	defer closeJWKS()

	random := mathrand.New(mathrand.NewSource(42))
	kmsClient := &kmsMock{random: random}
	enc, err := enclave.New(context.Background(), enclave.DummyProvider, kmsClient, privKey)
	require.NoError(t, err)

	sessWallet, err := ethwallet.NewWalletFromRandomEntropy()
	require.NoError(t, err)

	tenant, tntData := newTenant(t, enc, issuer)
	acc := newAccount(t, enc, issuer, sessWallet)
	sess := newSession(t, enc, issuer, sessWallet)

	walletAddr, err := rpc.AddressForUser(context.Background(), tntData, acc.UserID)
	require.NoError(t, err)

	dbClient := &dbMock{
		sessions: map[string]*data.Session{sess.ID: sess},
		tenants:  map[uint64][]*data.Tenant{tenant.ProjectID: {tenant}},
	}
	svc := initRPC(cfg, enc, dbClient)

	srv := httptest.NewServer(svc.Handler())
	defer srv.Close()

	packet := &packets.SendTransactionsPacket{
		BasePacketForWallet: packets.BasePacketForWallet{
			BasePacket: packets.BasePacket{
				Code:    packets.SendTransactionCode,
				Issued:  uint64(time.Now().Add(-1 * time.Second).Unix()),
				Expires: uint64(time.Now().Add(5 * time.Minute).Unix()),
			},
			Wallet: walletAddr,
		},
		Identifier: "identifier",
		Wallet:     walletAddr,
		Network:    "1",
		Transactions: []json.RawMessage{
			json.RawMessage(`{"data":"0x010203","to":"0x27CabC9700EE6Db2797b6AC1e1eCe81C72A2cD8D","type":"transaction","value":"0x2000000000"}`),
		},
	}
	intentJSON := generateIntent(t, sessWallet, packet)

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
	header.Set("X-Access-Key", newRandAccessKey(tenant.ProjectID))
	ctx, err := proto.WithHTTPRequestHeaders(context.Background(), header)

	resCode, resData, err := c.SendIntent(ctx, encryptedPayloadKey, payloadCiphertext, payloadSig)
	require.NoError(t, err)
	assert.Equal(t, "transactionReceipt", resCode)
	assert.NotEmpty(t, resData)
}

func TestRPC_SendIntent_GenericIntent(t *testing.T) {
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

	tenant, _ := newTenant(t, enc, issuer)
	sess := newSession(t, enc, issuer, sessWallet)

	dbClient := &dbMock{
		sessions: map[string]*data.Session{sess.ID: sess},
		tenants:  map[uint64][]*data.Tenant{tenant.ProjectID: {tenant}},
	}
	svc := initRPC(cfg, enc, dbClient)

	srv := httptest.NewServer(svc.Handler())
	defer srv.Close()

	packet := &proto.ListSessionsPacket{
		BasePacketForWallet: packets.BasePacketForWallet{
			BasePacket: packets.BasePacket{
				Code:    "genericIntent",
				Issued:  uint64(time.Now().Add(-1 * time.Second).Unix()),
				Expires: uint64(time.Now().Add(5 * time.Minute).Unix()),
			},
		},
	}
	intentJSON := generateIntent(t, sessWallet, packet)

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
	header.Set("X-Access-Key", newRandAccessKey(tenant.ProjectID))
	ctx, err := proto.WithHTTPRequestHeaders(context.Background(), header)

	resCode, resData, err := c.SendIntent(ctx, encryptedPayloadKey, payloadCiphertext, payloadSig)
	require.NoError(t, err)
	assert.Equal(t, "sentIntent", resCode)
	assert.NotEmpty(t, resData)
}
