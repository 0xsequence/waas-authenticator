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

	"github.com/0xsequence/ethkit/ethwallet"
	"github.com/0xsequence/ethkit/go-ethereum/common/hexutil"
	"github.com/0xsequence/ethkit/go-ethereum/crypto"
	"github.com/0xsequence/go-sequence/intents"
	"github.com/0xsequence/waas-authenticator/config"
	"github.com/0xsequence/waas-authenticator/data"
	"github.com/0xsequence/waas-authenticator/proto"
	"github.com/0xsequence/waas-authenticator/proto/builder"
	proto_wallet "github.com/0xsequence/waas-authenticator/proto/waas"
	"github.com/goccy/go-json"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEmailAuth(t *testing.T) {
	type assertionParams struct {
		tenant *data.Tenant
		email  string
	}

	testCases := map[string]struct {
		emailBuilderFn          func(t *testing.T, p assertionParams) string
		assertInitiateAuthFn    func(t *testing.T, res *proto.IntentResponse, err error) bool
		extractAnswerFn         func(t *testing.T, p assertionParams, res *proto.IntentResponse) string
		assertRegisterSessionFn func(t *testing.T, p assertionParams, sess *proto.Session, res *proto.IntentResponse, err error)
	}{
		"Success": {
			assertInitiateAuthFn: func(t *testing.T, res *proto.IntentResponse, err error) bool {
				require.NoError(t, err)
				require.NotNil(t, res)
				return true
			},
			extractAnswerFn: func(t *testing.T, p assertionParams, res *proto.IntentResponse) string {
				subject, message, found := getSentEmailMessage(t, p.email)
				require.True(t, found)
				assert.Equal(t, fmt.Sprintf("Login code for %d", p.tenant.ProjectID), subject)
				assert.Contains(t, message, "Your login code: ")
				return strings.TrimPrefix(message, "Your login code: ")
			},
			assertRegisterSessionFn: func(t *testing.T, p assertionParams, sess *proto.Session, res *proto.IntentResponse, err error) {
				require.NoError(t, err)
				require.NotNil(t, res)
				require.NotNil(t, sess)
			},
		},
		"CaseInsensitive": {
			emailBuilderFn: func(t *testing.T, p assertionParams) string {
				return fmt.Sprintf("  uSeR+%d@ExAmPlE.cOm  ", p.tenant.ProjectID)
			},
			assertInitiateAuthFn: func(t *testing.T, res *proto.IntentResponse, err error) bool {
				return true
			},
			extractAnswerFn: func(t *testing.T, p assertionParams, res *proto.IntentResponse) string {
				_, message, found := getSentEmailMessage(t, fmt.Sprintf("user+%d@example.com", p.tenant.ProjectID))
				require.True(t, found)
				return strings.TrimPrefix(message, "Your login code: ")
			},
			assertRegisterSessionFn: func(t *testing.T, p assertionParams, sess *proto.Session, res *proto.IntentResponse, err error) {
				expectedIdentity := newEmailIdentity(fmt.Sprintf("user+%d@example.com", p.tenant.ProjectID))
				require.NoError(t, err)
				assert.Equal(t, expectedIdentity, sess.Identity)
			},
		},
		"IncorrectCode": {
			assertInitiateAuthFn: func(t *testing.T, res *proto.IntentResponse, err error) bool {
				return true
			},
			extractAnswerFn: func(t *testing.T, p assertionParams, res *proto.IntentResponse) string {
				return "Wrong"
			},
			assertRegisterSessionFn: func(t *testing.T, p assertionParams, sess *proto.Session, res *proto.IntentResponse, err error) {
				require.ErrorContains(t, err, "incorrect answer")
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()

			sessWallet, err := ethwallet.NewWalletFromRandomEntropy()
			require.NoError(t, err)
			signingSession := intents.NewSessionP256K1(sessWallet)

			builderServer := httptest.NewServer(builder.NewBuilderServer(builder.NewMock()))
			defer builderServer.Close()
			walletService := newWalletServiceMock(nil)
			waasServer := httptest.NewServer(proto_wallet.NewWaaSServer(walletService))
			defer waasServer.Close()

			svc := initRPC(t, func(cfg *config.Config) {
				cfg.Builder.BaseURL = builderServer.URL
				cfg.Endpoints.WaasAPIServer = waasServer.URL
			})

			var p assertionParams
			p.tenant, _ = newTenantWithAuthConfig(t, svc.Enclave, proto.AuthConfig{
				Email: proto.AuthEmailConfig{
					Enabled: true,
				},
			})
			require.NoError(t, svc.Tenants.Add(ctx, p.tenant))

			if testCase.emailBuilderFn != nil {
				p.email = testCase.emailBuilderFn(t, p)
			} else {
				p.email = fmt.Sprintf("user+%d@example.com", p.tenant.ProjectID)
			}

			srv := httptest.NewServer(svc.Handler())
			defer srv.Close()

			c := proto.NewWaasAuthenticatorClient(srv.URL, http.DefaultClient)
			header := make(http.Header)
			header.Set("X-Sequence-Project", strconv.Itoa(int(p.tenant.ProjectID)))
			ctx, err = proto.WithHTTPRequestHeaders(context.Background(), header)
			require.NoError(t, err)

			initiateAuthData := intents.IntentDataInitiateAuth{
				SessionID:    signingSession.SessionID(),
				IdentityType: intents.IdentityType_Email,
				Verifier:     p.email + ";" + signingSession.SessionID(),
			}
			initiateAuth := generateSignedIntent(t, intents.IntentName_initiateAuth, initiateAuthData, signingSession)

			initiateAuthRes, err := c.SendIntent(ctx, initiateAuth)
			if testCase.assertInitiateAuthFn != nil {
				if proceed := testCase.assertInitiateAuthFn(t, initiateAuthRes, err); !proceed {
					return
				}
			}

			code := testCase.extractAnswerFn(t, p, initiateAuthRes)
			challenge := initiateAuthRes.Data.(map[string]any)["challenge"].(string)
			answer := hexutil.Encode(crypto.Keccak256([]byte(challenge + code)))

			openSessionData := intents.IntentDataOpenSession{
				SessionID:    signingSession.SessionID(),
				IdentityType: intents.IdentityType_Email,
				Verifier:     p.email + ";" + signingSession.SessionID(),
				Answer:       answer,
			}
			openSession := generateSignedIntent(t, intents.IntentName_openSession, openSessionData, signingSession)

			session, openSessionRes, err := c.RegisterSession(ctx, openSession, "friendly name")
			if testCase.assertRegisterSessionFn != nil {
				testCase.assertRegisterSessionFn(t, p, session, openSessionRes, err)
			}
		})
	}

}

func TestGuestAuth(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		ctx := context.Background()

		svc := initRPC(t)
		tenant, _ := newTenantWithAuthConfig(t, svc.Enclave, proto.AuthConfig{
			Guest: proto.AuthGuestConfig{
				Enabled: true,
			},
		})
		require.NoError(t, svc.Tenants.Add(ctx, tenant))

		srv := httptest.NewServer(svc.Handler())
		defer srv.Close()

		c := proto.NewWaasAuthenticatorClient(srv.URL, http.DefaultClient)
		header := make(http.Header)
		header.Set("X-Sequence-Project", strconv.Itoa(int(tenant.ProjectID)))
		ctx, err := proto.WithHTTPRequestHeaders(context.Background(), header)
		require.NoError(t, err)

		for i := 0; i < 10; i++ {
			sessWallet, err := ethwallet.NewWalletFromRandomEntropy()
			require.NoError(t, err)
			signingSession := intents.NewSessionP256K1(sessWallet)

			initiateAuth := generateSignedIntent(t, intents.IntentName_initiateAuth, intents.IntentDataInitiateAuth{
				SessionID:    signingSession.SessionID(),
				IdentityType: intents.IdentityType_Guest,
				Verifier:     signingSession.SessionID(),
			}, signingSession)
			initRes, err := c.SendIntent(ctx, initiateAuth)
			require.NoError(t, err)
			assert.Equal(t, proto.IntentResponseCode_authInitiated, initRes.Code)

			b, err := json.Marshal(initRes.Data)
			require.NoError(t, err)
			var initResData intents.IntentResponseAuthInitiated
			require.NoError(t, json.Unmarshal(b, &initResData))

			answer := crypto.Keccak256([]byte(*initResData.Challenge + signingSession.SessionID()))
			registerSession := generateSignedIntent(t, intents.IntentName_openSession, intents.IntentDataOpenSession{
				SessionID:    signingSession.SessionID(),
				IdentityType: intents.IdentityType_Guest,
				Verifier:     signingSession.SessionID(),
				Answer:       hexutil.Encode(answer),
			}, signingSession)
			sess, registerRes, err := c.RegisterSession(ctx, registerSession, "Friendly name")
			require.NoError(t, err)
			assert.Equal(t, "Guest:"+signingSession.SessionID(), sess.Identity.String())
			assert.Equal(t, proto.IntentResponseCode_sessionOpened, registerRes.Code)
		}
	})
}

func TestOIDCAuth(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		ctx := context.Background()

		exp := time.Now().Add(120 * time.Second)
		tokBuilderFn := func(b *jwt.Builder, url string) {
			b.Expiration(exp)
		}

		issuer, tok, closeJWKS := issueAccessTokenAndRunJwksServer(t, tokBuilderFn)
		defer closeJWKS()

		svc := initRPC(t)
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
	})
}

func TestStytchAuth(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		ctx := context.Background()

		exp := time.Now().Add(120 * time.Second)
		tokBuilderFn := func(b *jwt.Builder, url string) {
			b.Expiration(exp)
		}

		stytchServer, tok := issueAccessTokenAndRunStytchJwksServer(t, "project-123", tokBuilderFn)
		defer stytchServer.Close()

		svc := initRPCWithClient(t, &http.Client{Transport: testTransport{
			RoundTripper: http.DefaultTransport,
			modifyRequest: func(req *http.Request) {
				if strings.Contains(req.URL.String(), "stytch.com") {
					req.URL.Host = stytchServer.Listener.Addr().String()
				}
			},
		}})
		tenant, _ := newTenantWithAuthConfig(t, svc.Enclave, proto.AuthConfig{
			Stytch: proto.AuthStytchConfig{
				Enabled:   true,
				ProjectID: "project-123",
			},
		})
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
			IdentityType: intents.IdentityType_Stytch,
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
			IdentityType: intents.IdentityType_Stytch,
			Verifier:     verifier,
			Answer:       tok,
		}, signingSession)
		sess, registerRes, err := c.RegisterSession(ctx, registerSession, "Friendly name")
		require.NoError(t, err)
		assert.Equal(t, "Stytch:project-123#subject", sess.Identity.String())
		assert.Equal(t, proto.IntentResponseCode_sessionOpened, registerRes.Code)
	})
}

func TestPlayFabAuth(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		ctx := context.Background()

		playfabAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"data":{"AccountInfo":{"PlayFabId":"USER","PrivateInfo":{"Email":"user@example.com"}}}}`))
		}))
		defer playfabAPI.Close()

		svc := initRPCWithClient(t, &http.Client{Transport: testTransport{
			RoundTripper: http.DefaultTransport,
			modifyRequest: func(req *http.Request) {
				if strings.Contains(req.URL.String(), "playfabapi.com") {
					req.URL.Host = playfabAPI.Listener.Addr().String()
				}
			},
		}})
		tenant, _ := newTenantWithAuthConfig(t, svc.Enclave, proto.AuthConfig{
			Playfab: proto.AuthPlayfabConfig{
				Enabled: true,
				TitleID: "TITLE",
			},
		})
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

		ticket := "SESSION_TICKET"
		hashedTicket := hexutil.Encode(crypto.Keccak256([]byte(ticket)))
		verifier := "TITLE|" + hashedTicket
		initiateAuth := generateSignedIntent(t, intents.IntentName_initiateAuth, intents.IntentDataInitiateAuth{
			SessionID:    signingSession.SessionID(),
			IdentityType: intents.IdentityType_PlayFab,
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
			IdentityType: intents.IdentityType_PlayFab,
			Verifier:     verifier,
			Answer:       ticket,
		}, signingSession)
		sess, registerRes, err := c.RegisterSession(ctx, registerSession, "Friendly name")
		require.NoError(t, err)
		assert.Equal(t, "PlayFab:TITLE#USER", sess.Identity.String())
		assert.Equal(t, proto.IntentResponseCode_sessionOpened, registerRes.Code)
	})
}
