package rpc_test

import (
	"context"
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
	"github.com/0xsequence/waas-authenticator/proto"
	"github.com/goccy/go-json"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

func TestPlayFabAuth(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		ctx := context.Background()

		playfabAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"data":{"AccountInfo":{"PlayFabId":"USER","PrivateInfo":{"Email":"user@example.com"}}}}`))
		}))
		defer playfabAPI.Close()

		svc := initRPC(t, &http.Client{Transport: testTransport{
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
