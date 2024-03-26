package rpc_test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	mathrand "math/rand"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/0xsequence/ethkit/ethcoder"
	"github.com/0xsequence/ethkit/ethwallet"
	"github.com/0xsequence/go-sequence/intents"
	"github.com/0xsequence/nitrocontrol/enclave"
	"github.com/0xsequence/waas-authenticator/data"
	"github.com/0xsequence/waas-authenticator/proto"
	"github.com/0xsequence/waas-authenticator/rpc"
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
	signingSession := intents.NewSessionP256K1(sessWallet)
	sessHash := ethcoder.Keccak256Hash([]byte(signingSession.SessionID())).String()

	type assertionParams struct {
		tenant        *data.Tenant
		issuer        string
		dbClient      *dbMock
		walletService *walletServiceMock
	}
	testCases := map[string]struct {
		assertFn        func(t *testing.T, sess *proto.Session, err error, p assertionParams)
		tokBuilderFn    func(b *jwt.Builder, url string)
		intentBuilderFn func(t *testing.T, data intents.IntentDataOpenSession) *proto.Intent
	}{
		"Basic": {
			tokBuilderFn: func(b *jwt.Builder, url string) {
				b.Claim("sequence:session_hash", sessHash)
			},
			assertFn: func(t *testing.T, sess *proto.Session, err error, p assertionParams) {
				require.NoError(t, err)
				require.NotNil(t, sess)

				assert.Equal(t, signingSession.SessionID(), sess.ID)
				assert.Equal(t, fmt.Sprintf("%d|%s", p.tenant.ProjectID, sessHash), sess.UserID)
				assert.Equal(t, "FriendlyName", sess.FriendlyName)

				assert.Contains(t, p.dbClient.sessions, sess.ID)
				assert.Contains(t, p.dbClient.accounts[p.tenant.ProjectID], sess.Identity.String())
				assert.Contains(t, p.walletService.registeredSessions, sess.ID)
				assert.Contains(t, p.walletService.registeredUsers, sess.UserID)
			},
		},
		"WithInvalidIssuer": {
			tokBuilderFn: func(b *jwt.Builder, url string) { b.Issuer("https://id.example.com") },
			assertFn: func(t *testing.T, sess *proto.Session, err error, p assertionParams) {
				require.Nil(t, sess)
				require.ErrorContains(t, err, `issuer "https://id.example.com" not valid for this tenant`)
			},
		},
		"WithValidNonce": {
			tokBuilderFn: func(b *jwt.Builder, url string) { b.Claim("nonce", sessHash) },
			assertFn: func(t *testing.T, sess *proto.Session, err error, p assertionParams) {
				require.NoError(t, err)
				require.NotNil(t, sess)

				assert.Equal(t, signingSession.SessionID(), sess.ID)
			},
		},
		"WithInvalidNonce": {
			tokBuilderFn: func(b *jwt.Builder, url string) { b.Claim("nonce", "0x1234567890abcdef") },
			assertFn: func(t *testing.T, sess *proto.Session, err error, p assertionParams) {
				require.Nil(t, sess)
				require.ErrorContains(t, err, "JWT validation: nonce not satisfied")
			},
		},
		"WithMissingNonce": {
			assertFn: func(t *testing.T, sess *proto.Session, err error, p assertionParams) {
				require.Nil(t, sess)
				require.ErrorContains(t, err, "JWT validation: nonce not satisfied")
			},
		},
		"WithInvalidNonceButValidSessionAddressClaim": {
			tokBuilderFn: func(b *jwt.Builder, url string) {
				b.Claim("nonce", "0x1234567890abcdef").
					Claim("sequence:session_hash", sessHash)
			},
			assertFn: func(t *testing.T, sess *proto.Session, err error, p assertionParams) {
				require.NoError(t, err)
				require.NotNil(t, sess)

				assert.Equal(t, signingSession.SessionID(), sess.ID)
			},
		},
		"WithVerifiedEmail": {
			tokBuilderFn: func(b *jwt.Builder, url string) {
				b.Claim("email", "user@example.com").
					Claim("email_verified", "true").
					Claim("sequence:session_hash", sessHash)
			},
			assertFn: func(t *testing.T, sess *proto.Session, err error, p assertionParams) {
				require.NoError(t, err)
				require.NotNil(t, sess)

				assert.Equal(t, "user@example.com", sess.Identity.Email)
			},
		},
		"WithUnverifiedEmail": {
			tokBuilderFn: func(b *jwt.Builder, url string) {
				b.Claim("email", "user@example.com").
					Claim("email_verified", "false").
					Claim("sequence:session_hash", sessHash)
			},
			assertFn: func(t *testing.T, sess *proto.Session, err error, p assertionParams) {
				require.NoError(t, err)
				require.NotNil(t, sess)

				assert.Equal(t, "", sess.Identity.Email)
			},
		},
		"MissingSignature": {
			intentBuilderFn: func(t *testing.T, data intents.IntentDataOpenSession) *proto.Intent {
				return &proto.Intent{
					Version:    "1.0.0",
					Name:       proto.IntentName_openSession,
					ExpiresAt:  uint64(time.Now().Add(1 * time.Minute).Unix()),
					IssuedAt:   uint64(time.Now().Unix()),
					Data:       data,
					Signatures: nil,
				}
			},
			assertFn: func(t *testing.T, sess *proto.Session, err error, p assertionParams) {
				assert.ErrorContains(t, err, "intent is invalid: no signatures")
			},
		},
		"IssuerMissingScheme": {
			tokBuilderFn: func(b *jwt.Builder, url string) {
				b.Issuer(strings.TrimPrefix(url, "http://")).
					Claim("sequence:session_hash", sessHash)
			},
			assertFn: func(t *testing.T, sess *proto.Session, err error, p assertionParams) {
				require.NoError(t, err)
				require.NotNil(t, sess)

				httpsIssuer := "https://" + strings.TrimPrefix(p.issuer, "http://")
				assert.Equal(t, httpsIssuer, sess.Identity.Issuer)
			},
		},
	}

	for label, testCase := range testCases {
		t.Run(label, func(t *testing.T) {
			if testCase.intentBuilderFn == nil {
				testCase.intentBuilderFn = func(t *testing.T, data intents.IntentDataOpenSession) *proto.Intent {
					return generateSignedIntent(t, intents.IntentName_openSession, data, signingSession)
				}
			}

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

			intentData := intents.IntentDataOpenSession{
				SessionID: signingSession.SessionID(),
				IdToken:   &tok,
			}
			intent := testCase.intentBuilderFn(t, intentData)

			c := proto.NewWaasAuthenticatorClient(srv.URL, http.DefaultClient)
			header := make(http.Header)
			header.Set("X-Sequence-Project", strconv.Itoa(int(tenant.ProjectID)))
			ctx, err := proto.WithHTTPRequestHeaders(context.Background(), header)
			require.NoError(t, err)

			sess, _, err := c.RegisterSession(ctx, intent, "FriendlyName")
			testCase.assertFn(t, sess, err, assertionParams{
				tenant:        tenant,
				issuer:        issuer,
				dbClient:      dbClient,
				walletService: walletService,
			})
		})
	}
}

func TestRPC_SendIntent_DropSession(t *testing.T) {
	block, _ := pem.Decode([]byte(testPrivateKey))
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	require.NoError(t, err)

	sessWallet, err := ethwallet.NewWalletFromRandomEntropy()
	require.NoError(t, err)
	signingSession := intents.NewSessionP256K1(sessWallet)

	type assertionParams struct {
		tenant        *data.Tenant
		issuer        string
		dbClient      *dbMock
		walletService *walletServiceMock
	}
	testCases := map[string]struct {
		assertFn        func(t *testing.T, res *proto.IntentResponse, err error, p assertionParams)
		intentBuilderFn func(t *testing.T, data intents.IntentDataCloseSession) *proto.Intent
		dropSessionID   string
	}{
		"SameSession": {
			assertFn: func(t *testing.T, res *proto.IntentResponse, err error, p assertionParams) {
				require.NoError(t, err)
				require.NotNil(t, res)
				require.Equal(t, proto.IntentResponseCode_sessionClosed, res.Code)

				dropSession := signingSession.SessionID()
				assert.NotContains(t, p.dbClient.sessions, dropSession)
				assert.NotContains(t, p.walletService.registeredSessions, dropSession)
			},
			dropSessionID: signingSession.SessionID(),
		},
		"SameUser": {
			assertFn: func(t *testing.T, res *proto.IntentResponse, err error, p assertionParams) {
				require.NoError(t, err)
				require.NotNil(t, res)
				require.Equal(t, proto.IntentResponseCode_sessionClosed, res.Code)

				dropSession := "0x1111111111111111111111111111111111111111"
				assert.NotContains(t, p.dbClient.sessions, dropSession)
				assert.NotContains(t, p.walletService.registeredSessions, dropSession)
			},
			dropSessionID: "0x1111111111111111111111111111111111111111",
		},
		"OtherUser": {
			assertFn: func(t *testing.T, res *proto.IntentResponse, err error, p assertionParams) {
				assert.ErrorContains(t, err, "session not found")
				assert.Nil(t, res)

				dropSession := "0x2222222222222222222222222222222222222222"
				assert.Contains(t, p.dbClient.sessions, dropSession)
				assert.Contains(t, p.walletService.registeredSessions, dropSession)
			},
			dropSessionID: "0x2222222222222222222222222222222222222222",
		},
	}

	for label, testCase := range testCases {
		t.Run(label, func(t *testing.T) {
			if testCase.intentBuilderFn == nil {
				testCase.intentBuilderFn = func(t *testing.T, data intents.IntentDataCloseSession) *proto.Intent {
					return generateSignedIntent(t, intents.IntentName_closeSession, data, signingSession)
				}
			}

			cfg := initConfig(t)

			issuer, _, closeJWKS := issueAccessTokenAndRunJwksServer(t)
			defer closeJWKS()

			random := mathrand.New(mathrand.NewSource(42))
			kmsClient := &kmsMock{random: random}
			enc, err := enclave.New(context.Background(), enclave.DummyProvider, kmsClient, privKey)
			require.NoError(t, err)

			tenant, _ := newTenant(t, enc, issuer)
			acc := newAccount(t, enc, issuer, sessWallet)
			session := newSession(t, enc, issuer, signingSession)

			session2 := newSessionFromData(t, enc, &proto.SessionData{
				ID:        "0x1111111111111111111111111111111111111111",
				ProjectID: 1,
				UserID:    session.UserID,
				Identity:  session.Identity,
				CreatedAt: time.Now(),
				ExpiresAt: time.Now().Add(1 * time.Minute),
			})

			session3 := newSessionFromData(t, enc, &proto.SessionData{
				ID:        "0x2222222222222222222222222222222222222222",
				ProjectID: 1,
				UserID:    "ANOTHER-USER",
				Identity:  session.Identity,
				CreatedAt: time.Now(),
				ExpiresAt: time.Now().Add(1 * time.Minute),
			})

			dbClient := &dbMock{
				sessions: map[string]*data.Session{
					session.ID:  session,
					session2.ID: session2,
					session3.ID: session3,
				},
				tenants: map[uint64][]*data.Tenant{tenant.ProjectID: {tenant}},
				accounts: map[uint64]map[string]*data.Account{
					tenant.ProjectID: {acc.UserID: acc},
				},
			}
			svc := initRPC(cfg, enc, dbClient)
			walletService := newWalletServiceMock([]string{session.ID, session2.ID, session3.ID})
			svc.Wallets = walletService

			srv := httptest.NewServer(svc.Handler())
			defer srv.Close()

			intentData := intents.IntentDataCloseSession{
				SessionID: testCase.dropSessionID,
			}
			intent := testCase.intentBuilderFn(t, intentData)

			c := proto.NewWaasAuthenticatorClient(srv.URL, http.DefaultClient)
			header := make(http.Header)
			header.Set("X-Sequence-Project", strconv.Itoa(int(tenant.ProjectID)))
			ctx, err := proto.WithHTTPRequestHeaders(context.Background(), header)

			res, err := c.SendIntent(ctx, intent)
			testCase.assertFn(t, res, err, assertionParams{
				tenant:        tenant,
				issuer:        issuer,
				dbClient:      dbClient,
				walletService: walletService,
			})
		})
	}
}

func TestRPC_SendIntent_ListSessions(t *testing.T) {
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
	signingSession := intents.NewSessionP256K1(sessWallet)

	tenant, tntData := newTenant(t, enc, issuer)
	acc := newAccount(t, enc, issuer, sessWallet)
	sess1 := newSession(t, enc, issuer, signingSession)
	sess2 := newSessionFromData(t, enc, &proto.SessionData{
		ID:        "0x1111111111111111111111111111111111111111",
		ProjectID: 1,
		UserID:    sess1.UserID,
		Identity:  sess1.Identity,
	})
	sess3 := newSessionFromData(t, enc, &proto.SessionData{
		ID:        "0x2222222222222222222222222222222222222222",
		ProjectID: 1,
		UserID:    "ANOTHER-USER",
		Identity:  sess1.Identity,
	})

	walletAddr, err := rpc.AddressForUser(context.Background(), tntData, acc.UserID)
	require.NoError(t, err)

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

	intentData := &intents.IntentDataListSessions{
		Wallet: walletAddr,
	}
	intent := generateSignedIntent(t, intents.IntentName_listSessions, intentData, signingSession)

	c := proto.NewWaasAuthenticatorClient(srv.URL, http.DefaultClient)
	header := make(http.Header)
	header.Set("X-Sequence-Project", strconv.Itoa(int(tenant.ProjectID)))
	ctx, err := proto.WithHTTPRequestHeaders(context.Background(), header)
	require.NoError(t, err)

	res, err := c.SendIntent(ctx, intent)
	require.NoError(t, err)
	assert.Equal(t, proto.IntentResponseCode_sessionList, res.Code)

	sessions, ok := res.Data.([]any)
	require.True(t, ok)
	require.Len(t, sessions, 2)
}
