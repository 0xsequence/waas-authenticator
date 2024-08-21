package rpc_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/0xsequence/ethkit/ethwallet"
	"github.com/0xsequence/ethkit/go-ethereum/common/hexutil"
	"github.com/0xsequence/ethkit/go-ethereum/crypto"
	"github.com/0xsequence/go-sequence/intents"
	"github.com/0xsequence/waas-authenticator/config"
	"github.com/0xsequence/waas-authenticator/data"
	"github.com/0xsequence/waas-authenticator/proto"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMigrationOIDCToStytch(t *testing.T) {
	t.Run("WithoutConfig", func(t *testing.T) {
		t.Run("NoContinuousMigration", func(t *testing.T) {
			ctx := context.Background()

			exp := time.Now().Add(120 * time.Second)
			tokBuilderFn := func(b *jwt.Builder, url string) {
				b.Expiration(exp)
			}

			issuer, tok, closeJWKS := issueAccessTokenAndRunJwksServer(t, tokBuilderFn)
			defer closeJWKS()

			svc := initRPC(t, func(cfg *config.Config) {
				cfg.Migrations.OIDCToStytch = []config.OIDCToStytchConfig{
					{
						SequenceProject: currentProjectID.Load() + 1,
						StytchProject:   "TEST",
						FromIssuer:      "FAKE_ISSUER",
					},
				}
			})
			tenant, _ := newTenant(t, svc.Enclave, issuer)
			require.NoError(t, svc.Tenants.Add(ctx, tenant))

			sessWallet, err := ethwallet.NewWalletFromRandomEntropy()
			require.NoError(t, err)
			signingSession := intents.NewSessionP256K1(sessWallet)

			srv := httptest.NewServer(svc.Handler())
			defer srv.Close()

			c := proto.NewWaasAuthenticatorClient(srv.URL, http.DefaultClient)
			header := make(http.Header)
			header.Set("X-Sequence-Project", strconv.Itoa(int(tenant.ProjectID)))
			ctx, err = proto.WithHTTPRequestHeaders(context.Background(), header)
			require.NoError(t, err)

			hashedToken := hexutil.Encode(crypto.Keccak256([]byte(tok)))
			verifier := hashedToken + ";" + strconv.Itoa(int(exp.Unix()))
			initiateAuth := generateSignedIntent(t, intents.IntentName_initiateAuth, intents.IntentDataInitiateAuth{
				SessionID:    signingSession.SessionID(),
				IdentityType: intents.IdentityType_OIDC,
				Verifier:     verifier,
			}, signingSession)
			initRes, err := c.SendIntent(ctx, initiateAuth)
			require.NoError(t, err)
			assert.Equal(t, proto.IntentResponseCode_authInitiated, initRes.Code)

			b, err := json.Marshal(initRes.Data)
			require.NoError(t, err)
			var initResData intents.IntentResponseAuthInitiated
			require.NoError(t, json.Unmarshal(b, &initResData))

			registerSession := generateSignedIntent(t, intents.IntentName_openSession, intents.IntentDataOpenSession{
				SessionID:    signingSession.SessionID(),
				IdentityType: intents.IdentityType_OIDC,
				Verifier:     verifier,
				Answer:       tok,
			}, signingSession)
			sess, registerRes, err := c.RegisterSession(ctx, registerSession, "Friendly name")
			require.NoError(t, err)
			assert.Equal(t, "OIDC:"+issuer+"#subject", sess.Identity.String())
			assert.Equal(t, proto.IntentResponseCode_sessionOpened, registerRes.Code)

			accs, _, err := svc.Accounts.ListByProjectAndIdentity(ctx, data.Page{}, tenant.ProjectID, proto.IdentityType_Stytch, "")
			require.NoError(t, err)
			assert.Len(t, accs, 0)
		})
	})

	t.Run("ContinuousMigration", func(t *testing.T) {
		ctx := context.Background()

		exp := time.Now().Add(120 * time.Second)
		tokBuilderFn := func(b *jwt.Builder, url string) {
			b.Expiration(exp)
		}

		issuer, tok, closeJWKS := issueAccessTokenAndRunJwksServer(t, tokBuilderFn)
		defer closeJWKS()

		svc := initRPC(t, func(cfg *config.Config) {
			cfg.Migrations.OIDCToStytch = []config.OIDCToStytchConfig{
				{
					SequenceProject: currentProjectID.Load() + 1,
					StytchProject:   "TEST",
					FromIssuer:      issuer,
				},
			}
		})
		tenant, _ := newTenant(t, svc.Enclave, issuer)
		require.NoError(t, svc.Tenants.Add(ctx, tenant))

		sessWallet, err := ethwallet.NewWalletFromRandomEntropy()
		require.NoError(t, err)
		signingSession := intents.NewSessionP256K1(sessWallet)

		srv := httptest.NewServer(svc.Handler())
		defer srv.Close()

		c := proto.NewWaasAuthenticatorClient(srv.URL, http.DefaultClient)
		header := make(http.Header)
		header.Set("X-Sequence-Project", strconv.Itoa(int(tenant.ProjectID)))
		ctx, err = proto.WithHTTPRequestHeaders(context.Background(), header)
		require.NoError(t, err)

		hashedToken := hexutil.Encode(crypto.Keccak256([]byte(tok)))
		verifier := hashedToken + ";" + strconv.Itoa(int(exp.Unix()))
		initiateAuth := generateSignedIntent(t, intents.IntentName_initiateAuth, intents.IntentDataInitiateAuth{
			SessionID:    signingSession.SessionID(),
			IdentityType: intents.IdentityType_OIDC,
			Verifier:     verifier,
		}, signingSession)
		initRes, err := c.SendIntent(ctx, initiateAuth)
		require.NoError(t, err)
		assert.Equal(t, proto.IntentResponseCode_authInitiated, initRes.Code)

		b, err := json.Marshal(initRes.Data)
		require.NoError(t, err)
		var initResData intents.IntentResponseAuthInitiated
		require.NoError(t, json.Unmarshal(b, &initResData))

		registerSession := generateSignedIntent(t, intents.IntentName_openSession, intents.IntentDataOpenSession{
			SessionID:    signingSession.SessionID(),
			IdentityType: intents.IdentityType_OIDC,
			Verifier:     verifier,
			Answer:       tok,
		}, signingSession)
		sess, registerRes, err := c.RegisterSession(ctx, registerSession, "Friendly name")
		require.NoError(t, err)
		assert.Equal(t, "OIDC:"+issuer+"#subject", sess.Identity.String())
		assert.Equal(t, proto.IntentResponseCode_sessionOpened, registerRes.Code)

		expectedIdentity := proto.Identity{
			Type:    proto.IdentityType_Stytch,
			Issuer:  "TEST",
			Subject: "subject",
		}
		accs, _, err := svc.Accounts.ListByProjectAndIdentity(ctx, data.Page{}, tenant.ProjectID, proto.IdentityType_Stytch, "")
		require.NoError(t, err)
		require.Len(t, accs, 1)
		assert.Equal(t, expectedIdentity, proto.Identity(accs[0].Identity))
		assert.Equal(t, sess.UserID, accs[0].UserID)
	})

	t.Run("OneTimeMigration", func(t *testing.T) {
		ctx := context.Background()

		issuer, _, closeJWKS := issueAccessTokenAndRunJwksServer(t)
		defer closeJWKS()

		projectID := currentProjectID.Load() + 1
		svc := initRPC(t, func(cfg *config.Config) {
			cfg.Migrations.OIDCToStytch = []config.OIDCToStytchConfig{
				{
					SequenceProject: projectID,
					StytchProject:   "TEST",
					FromIssuer:      issuer,
				},
			}
		})
		tenant, _ := newTenant(t, svc.Enclave, issuer)
		require.NoError(t, svc.Tenants.Add(ctx, tenant))
		require.Equal(t, projectID, tenant.ProjectID)
		account := newAccount(t, tenant, svc.Enclave, newOIDCIdentity(issuer), nil)
		require.NoError(t, svc.Accounts.Put(ctx, account))

		// Add more accounts
		for i := 0; i < 10; i++ {
			acc := newAccount(t, tenant, svc.Enclave, newOIDCIdentity(issuer, fmt.Sprintf("acc-%d", i)), nil)
			require.NoError(t, svc.Accounts.Put(ctx, acc))
		}

		srv := httptest.NewServer(svc.Handler())
		defer srv.Close()

		c := proto.NewWaasAuthenticatorAdminClient(srv.URL, http.DefaultClient)
		header := make(http.Header)
		header.Set("Authorization", "Bearer "+adminJWT)
		ctx, err := proto.WithHTTPRequestHeaders(context.Background(), header)
		require.NoError(t, err)

		_, items, err := c.NextMigrationBatch(ctx, proto.Migration_OIDCToStytch, tenant.ProjectID, nil)
		require.NoError(t, err)
		require.Len(t, items, 11)

		itemLogs, itemErrors, err := c.ProcessMigrationBatch(ctx, proto.Migration_OIDCToStytch, tenant.ProjectID, items)
		require.NoError(t, err)
		assert.Empty(t, itemLogs)
		assert.Empty(t, itemErrors)

		// There should be now 2 accounts of the original user: original + stytch
		resultAccounts, err := svc.Accounts.ListByUserID(ctx, account.UserID)
		require.NoError(t, err)
		require.Len(t, resultAccounts, 2)

		identities := make([]proto.Identity, len(resultAccounts))
		for i, acc := range resultAccounts {
			identities[i] = proto.Identity(acc.Identity)
		}
		assert.Contains(t, identities, newStytchIdentity("TEST"))

		// 2 accounts of original user + 10 doubled (migrated) additional users
		allAccounts, _, err := svc.Accounts.ListByProjectAndIdentity(ctx, data.Page{}, tenant.ProjectID, proto.IdentityType_None, "")
		require.NoError(t, err)
		require.Len(t, allAccounts, 22)
	})
}

func TestMigrationEmail(t *testing.T) {
	t.Run("ContinuousMigration", func(t *testing.T) {
		ctx := context.Background()

		sessWallet, err := ethwallet.NewWalletFromRandomEntropy()
		require.NoError(t, err)
		signingSession := intents.NewSessionP256K1(sessWallet)

		exp := time.Now().Add(120 * time.Second)
		tokBuilderFn := func(b *jwt.Builder, url string) {
			b.Expiration(exp)
			b.Claim("email", signingSession.SessionID()+"@example.com")
		}

		issuer, tok, closeJWKS := issueAccessTokenAndRunJwksServer(t, tokBuilderFn)
		defer closeJWKS()

		svc := initRPC(t, func(cfg *config.Config) {
			cfg.Migrations.Email = config.EmailMigrationConfig{
				Enabled:      true,
				IssuerPrefix: issuer,
			}
		})
		tenant, _ := newTenant(t, svc.Enclave, issuer)
		require.NoError(t, svc.Tenants.Add(ctx, tenant))

		srv := httptest.NewServer(svc.Handler())
		defer srv.Close()

		c := proto.NewWaasAuthenticatorClient(srv.URL, http.DefaultClient)
		header := make(http.Header)
		header.Set("X-Sequence-Project", strconv.Itoa(int(tenant.ProjectID)))
		ctx, err = proto.WithHTTPRequestHeaders(context.Background(), header)
		require.NoError(t, err)

		hashedToken := hexutil.Encode(crypto.Keccak256([]byte(tok)))
		verifier := hashedToken + ";" + strconv.Itoa(int(exp.Unix()))
		initiateAuth := generateSignedIntent(t, intents.IntentName_initiateAuth, intents.IntentDataInitiateAuth{
			SessionID:    signingSession.SessionID(),
			IdentityType: intents.IdentityType_OIDC,
			Verifier:     verifier,
		}, signingSession)
		initRes, err := c.SendIntent(ctx, initiateAuth)
		require.NoError(t, err)
		assert.Equal(t, proto.IntentResponseCode_authInitiated, initRes.Code)

		b, err := json.Marshal(initRes.Data)
		require.NoError(t, err)
		var initResData intents.IntentResponseAuthInitiated
		require.NoError(t, json.Unmarshal(b, &initResData))

		registerSession := generateSignedIntent(t, intents.IntentName_openSession, intents.IntentDataOpenSession{
			SessionID:    signingSession.SessionID(),
			IdentityType: intents.IdentityType_OIDC,
			Verifier:     verifier,
			Answer:       tok,
		}, signingSession)
		sess, registerRes, err := c.RegisterSession(ctx, registerSession, "Friendly name")
		require.NoError(t, err)
		assert.Equal(t, "OIDC:"+issuer+"#subject", sess.Identity.String())
		assert.Equal(t, proto.IntentResponseCode_sessionOpened, registerRes.Code)

		expectedIdentity := proto.Identity{
			Type:    proto.IdentityType_Email,
			Subject: signingSession.SessionID() + "@example.com",
		}
		accs, _, err := svc.Accounts.ListByProjectAndIdentity(ctx, data.Page{}, tenant.ProjectID, proto.IdentityType_Email, "")
		require.NoError(t, err)
		require.Len(t, accs, 1)
		assert.Equal(t, expectedIdentity, proto.Identity(accs[0].Identity))
		assert.Equal(t, sess.UserID, accs[0].UserID)
	})

	t.Run("OneTimeMigration", func(t *testing.T) {
		ctx := context.Background()

		issuer, _, closeJWKS := issueAccessTokenAndRunJwksServer(t)
		defer closeJWKS()

		projectID := currentProjectID.Load() + 1
		svc := initRPC(t, func(cfg *config.Config) {
			cfg.Migrations.Email = config.EmailMigrationConfig{
				Enabled:      true,
				IssuerPrefix: issuer,
			}
		})
		tenant, _ := newTenant(t, svc.Enclave, issuer)
		require.NoError(t, svc.Tenants.Add(ctx, tenant))
		require.Equal(t, projectID, tenant.ProjectID)
		account := newAccount(t, tenant, svc.Enclave, newOIDCIdentity(issuer), nil)
		require.NoError(t, svc.Accounts.Put(ctx, account))

		// Add more accounts
		for i := 0; i < 10; i++ {
			sub := fmt.Sprintf("acc-%d", i)
			acc := newAccount(t, tenant, svc.Enclave, newOIDCIdentity(issuer, sub), nil, sub+"@example.com")
			require.NoError(t, svc.Accounts.Put(ctx, acc))
		}

		srv := httptest.NewServer(svc.Handler())
		defer srv.Close()

		c := proto.NewWaasAuthenticatorAdminClient(srv.URL, http.DefaultClient)
		header := make(http.Header)
		header.Set("Authorization", "Bearer "+adminJWT)
		ctx, err := proto.WithHTTPRequestHeaders(context.Background(), header)
		require.NoError(t, err)

		_, items, err := c.NextMigrationBatch(ctx, proto.Migration_OIDCToEmail, tenant.ProjectID, nil)
		require.NoError(t, err)
		require.Len(t, items, 11)

		itemLogs, itemErrors, err := c.ProcessMigrationBatch(ctx, proto.Migration_OIDCToEmail, tenant.ProjectID, items)
		require.NoError(t, err)
		assert.Empty(t, itemLogs)
		assert.Empty(t, itemErrors)

		// There should be now 2 accounts of the original user: original + native email
		resultAccounts, err := svc.Accounts.ListByUserID(ctx, account.UserID)
		require.NoError(t, err)
		require.Len(t, resultAccounts, 2)

		identities := make([]proto.Identity, len(resultAccounts))
		for i, acc := range resultAccounts {
			identities[i] = proto.Identity(acc.Identity)
		}
		assert.Contains(t, identities, newEmailIdentity(account.Email))

		// 2 accounts of original user + 10 doubled (migrated) additional users
		allAccounts, _, err := svc.Accounts.ListByProjectAndIdentity(ctx, data.Page{}, tenant.ProjectID, proto.IdentityType_None, "")
		require.NoError(t, err)
		require.Len(t, allAccounts, 22)
	})
}
