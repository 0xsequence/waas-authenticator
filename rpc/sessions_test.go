package rpc_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/0xsequence/ethkit/ethcoder"
	"github.com/0xsequence/ethkit/ethwallet"
	"github.com/0xsequence/go-sequence/intents"
	"github.com/0xsequence/waas-authenticator/data"
	"github.com/0xsequence/waas-authenticator/proto"
	"github.com/0xsequence/waas-authenticator/rpc"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRPC_RegisterSession(t *testing.T) {
	sessWallet, err := ethwallet.NewWalletFromRandomEntropy()
	require.NoError(t, err)
	signingSession := intents.NewSessionP256K1(sessWallet)
	sessHash := ethcoder.Keccak256Hash([]byte(signingSession.SessionID())).String()

	type assertionParams struct {
		svc           *rpc.RPC
		tenant        *data.Tenant
		issuer        string
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

				assert.Contains(t, p.walletService.registeredSessions, sess.ID)
				assert.Contains(t, p.walletService.registeredUsers, sess.UserID)

				_, found, err := p.svc.Sessions.Get(context.Background(), p.tenant.ProjectID, sess.ID)
				require.NoError(t, err)
				require.True(t, found)

				_, found, err = p.svc.Accounts.Get(context.Background(), p.tenant.ProjectID, sess.Identity)
				require.NoError(t, err)
				require.True(t, found)
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
				b.Claim("email", "123@example.com").
					Claim("email_verified", "true").
					Claim("sequence:session_hash", sessHash)
			},
			assertFn: func(t *testing.T, sess *proto.Session, err error, p assertionParams) {
				require.NoError(t, err)
				require.NotNil(t, sess)

				assert.Equal(t, "123@example.com", sess.Identity.Email)
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
		"EmailAlreadyInUse": {
			tokBuilderFn: func(b *jwt.Builder, url string) {
				b.Claim("email", "user@example.com").
					Claim("sequence:session_hash", sessHash)
			},
			assertFn: func(t *testing.T, sess *proto.Session, err error, p assertionParams) {
				assert.ErrorIs(t, err, proto.ErrEmailAlreadyInUse)
				assert.Nil(t, sess)
			},
		},
		"EmailAlreadyInUseWithForceCreateAccount": {
			intentBuilderFn: func(t *testing.T, data intents.IntentDataOpenSession) *proto.Intent {
				data.ForceCreateAccount = true
				return generateSignedIntent(t, intents.IntentName_openSession, data, signingSession)
			},
			tokBuilderFn: func(b *jwt.Builder, url string) {
				b.Claim("email", "user@example.com").
					Claim("sequence:session_hash", sessHash)
			},
			assertFn: func(t *testing.T, sess *proto.Session, err error, p assertionParams) {
				require.NoError(t, err)
				require.NotNil(t, sess)

				assert.Contains(t, p.walletService.registeredSessions, sess.ID)
				assert.Contains(t, p.walletService.registeredUsers, sess.UserID)

				_, found, err := p.svc.Sessions.Get(context.Background(), p.tenant.ProjectID, sess.ID)
				require.NoError(t, err)
				require.True(t, found)

				_, found, err = p.svc.Accounts.Get(context.Background(), p.tenant.ProjectID, sess.Identity)
				require.NoError(t, err)
				require.True(t, found)
			},
		},
	}

	for label, testCase := range testCases {
		t.Run(label, func(t *testing.T) {
			ctx := context.Background()

			if testCase.intentBuilderFn == nil {
				testCase.intentBuilderFn = func(t *testing.T, data intents.IntentDataOpenSession) *proto.Intent {
					return generateSignedIntent(t, intents.IntentName_openSession, data, signingSession)
				}
			}

			issuer, tok, closeJWKS := issueAccessTokenAndRunJwksServer(t, testCase.tokBuilderFn)
			defer closeJWKS()

			svc := initRPC(t)
			walletService := newWalletServiceMock(nil)
			svc.Wallets = walletService

			tenant, _ := newTenant(t, svc.Enclave, issuer)
			account := newAccount(t, tenant, svc.Enclave, "http://another-issuer", nil)

			require.NoError(t, svc.Tenants.Add(ctx, tenant))
			require.NoError(t, svc.Accounts.Put(ctx, account))

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
				svc:           svc,
				tenant:        tenant,
				issuer:        issuer,
				walletService: walletService,
			})
		})
	}
}

func TestRPC_SendIntent_DropSession(t *testing.T) {
	sessWallet, err := ethwallet.NewWalletFromRandomEntropy()
	require.NoError(t, err)
	signingSession := intents.NewSessionP256K1(sessWallet)

	type assertionParams struct {
		svc           *rpc.RPC
		tenant        *data.Tenant
		issuer        string
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
				assert.NotContains(t, p.walletService.registeredSessions, dropSession)
				_, found, err := p.svc.Sessions.Get(context.Background(), p.tenant.ProjectID, dropSession)
				require.NoError(t, err)
				require.False(t, found)
			},
			dropSessionID: signingSession.SessionID(),
		},
		"SameUser": {
			assertFn: func(t *testing.T, res *proto.IntentResponse, err error, p assertionParams) {
				require.NoError(t, err)
				require.NotNil(t, res)
				require.Equal(t, proto.IntentResponseCode_sessionClosed, res.Code)

				dropSession := "0x1111111111111111111111111111111111111111"
				assert.NotContains(t, p.walletService.registeredSessions, dropSession)
				_, found, err := p.svc.Sessions.Get(context.Background(), p.tenant.ProjectID, dropSession)
				require.NoError(t, err)
				require.False(t, found)
			},
			dropSessionID: "0x1111111111111111111111111111111111111111",
		},
		"OtherUser": {
			assertFn: func(t *testing.T, res *proto.IntentResponse, err error, p assertionParams) {
				// Returns no error...
				require.NoError(t, err)
				require.NotNil(t, res)
				require.Equal(t, proto.IntentResponseCode_sessionClosed, res.Code)

				// ...but the session is not dropped
				dropSession := "0x2222222222222222222222222222222222222222"
				assert.Contains(t, p.walletService.registeredSessions, dropSession)
				_, found, err := p.svc.Sessions.Get(context.Background(), p.tenant.ProjectID, dropSession)
				require.NoError(t, err)
				require.True(t, found)
			},
			dropSessionID: "0x2222222222222222222222222222222222222222",
		},
	}

	for label, testCase := range testCases {
		t.Run(label, func(t *testing.T) {
			ctx := context.Background()

			if testCase.intentBuilderFn == nil {
				testCase.intentBuilderFn = func(t *testing.T, data intents.IntentDataCloseSession) *proto.Intent {
					return generateSignedIntent(t, intents.IntentName_closeSession, data, signingSession)
				}
			}

			issuer, _, closeJWKS := issueAccessTokenAndRunJwksServer(t)
			defer closeJWKS()

			svc := initRPC(t)

			tenant, _ := newTenant(t, svc.Enclave, issuer)
			acc := newAccount(t, tenant, svc.Enclave, issuer, sessWallet)
			session := newSession(t, tenant, svc.Enclave, issuer, signingSession)

			session2 := newSessionFromData(t, tenant, svc.Enclave, &proto.SessionData{
				ID:        "0x1111111111111111111111111111111111111111",
				ProjectID: 1,
				UserID:    session.UserID,
				Identity:  session.Identity,
				CreatedAt: time.Now(),
				ExpiresAt: time.Now().Add(1 * time.Minute),
			})

			session3 := newSessionFromData(t, tenant, svc.Enclave, &proto.SessionData{
				ID:        "0x2222222222222222222222222222222222222222",
				ProjectID: 1,
				UserID:    "ANOTHER-USER",
				Identity:  session.Identity,
				CreatedAt: time.Now(),
				ExpiresAt: time.Now().Add(1 * time.Minute),
			})

			require.NoError(t, svc.Tenants.Add(ctx, tenant))
			require.NoError(t, svc.Accounts.Put(ctx, acc))
			require.NoError(t, svc.Sessions.Put(ctx, session))
			require.NoError(t, svc.Sessions.Put(ctx, session2))
			require.NoError(t, svc.Sessions.Put(ctx, session3))

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
				svc:           svc,
				tenant:        tenant,
				issuer:        issuer,
				walletService: walletService,
			})
		})
	}
}

func TestRPC_SendIntent_ListSessions(t *testing.T) {
	ctx := context.Background()

	issuer, _, closeJWKS := issueAccessTokenAndRunJwksServer(t)
	defer closeJWKS()

	sessWallet, err := ethwallet.NewWalletFromRandomEntropy()
	require.NoError(t, err)
	signingSession := intents.NewSessionP256K1(sessWallet)

	svc := initRPC(t)

	tenant, tntData := newTenant(t, svc.Enclave, issuer)
	acc := newAccount(t, tenant, svc.Enclave, issuer, sessWallet)
	sess1 := newSession(t, tenant, svc.Enclave, issuer, signingSession)
	sess2 := newSessionFromData(t, tenant, svc.Enclave, &proto.SessionData{
		ID:        "0x1111111111111111111111111111111111111111",
		ProjectID: 1,
		UserID:    sess1.UserID,
		Identity:  sess1.Identity,
	})
	sess3 := newSessionFromData(t, tenant, svc.Enclave, &proto.SessionData{
		ID:        "0x2222222222222222222222222222222222222222",
		ProjectID: 1,
		UserID:    "ANOTHER-USER",
		Identity:  sess1.Identity,
	})

	walletAddr, err := rpc.AddressForUser(context.Background(), tntData, acc.UserID)
	require.NoError(t, err)

	require.NoError(t, svc.Tenants.Add(ctx, tenant))
	require.NoError(t, svc.Accounts.Put(ctx, acc))
	require.NoError(t, svc.Sessions.Put(ctx, sess1))
	require.NoError(t, svc.Sessions.Put(ctx, sess2))
	require.NoError(t, svc.Sessions.Put(ctx, sess3))

	walletService := newWalletServiceMock([]string{sess1.ID, sess2.ID, sess3.ID})
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
	ctx, err = proto.WithHTTPRequestHeaders(context.Background(), header)
	require.NoError(t, err)

	res, err := c.SendIntent(ctx, intent)
	require.NoError(t, err)
	assert.Equal(t, proto.IntentResponseCode_sessionList, res.Code)

	sessions, ok := res.Data.([]any)
	require.True(t, ok)
	require.Len(t, sessions, 2)
}
