package rpc_test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	mathrand "math/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/0xsequence/nitrocontrol/enclave"
	"github.com/0xsequence/waas-authenticator/data"
	"github.com/0xsequence/waas-authenticator/proto"
	"github.com/goware/validation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const adminJWT = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJoZWxsbyI6IndvcmxkIn0.etvI60-iOY2f9a3d1SBYmbrDllxcYm0rF8tB5YyUWwFMBSArAFG8a6ms1k3OtR9xe8uLTeeOC80eLOMWSUgQd_TZmu5RPNBYMMhcqWnl5H64chO2sFrRDdxUCnNYRccEnDesQACmqaf1bbDCFs8Hwh2O4_rHoscuJ7kb3XBCC2a52Dyh8EYTEXg8DJGmUFQX5XKKb35uurejcKo_5yK2onr26SVm_arl4CCcDeNITv1mP1aGvroj1PUVGTpnd9mScPAoecmihdiMMF9VdXU3KGNvK-l44Miq9-a9mnwOwZNtoxqQxlh-cmcNAV5cGh66zfbPnWKb9t9YrMY4wKtshg"

func TestRPC_GetTenant(t *testing.T) {
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

	tenant, _ := newTenant(t, enc, issuer)
	dbClient := &dbMock{
		sessions: map[string]*data.Session{},
		tenants:  map[uint64][]*data.Tenant{tenant.ProjectID: {tenant}},
	}
	svc := initRPC(cfg, enc, dbClient)

	srv := httptest.NewServer(svc.Handler())
	defer srv.Close()

	c := proto.NewWaasAuthenticatorAdminClient(srv.URL, http.DefaultClient)
	header := make(http.Header)
	header.Set("Authorization", "Bearer "+adminJWT)
	ctx, err := proto.WithHTTPRequestHeaders(context.Background(), header)

	t.Run("ExistingTenant", func(t *testing.T) {
		tnt, err := c.GetTenant(ctx, 1)
		require.NoError(t, err)
		assert.NotEmpty(t, tnt)
		assert.Equal(t, uint64(1), tnt.ProjectID)
		assert.Equal(t, validation.Origins{"http://localhost"}, tnt.AllowedOrigins)
	})

	t.Run("MissingTenant", func(t *testing.T) {
		tnt, err := c.GetTenant(ctx, 2)
		assert.ErrorIs(t, err, proto.ErrTenantNotFound)
		assert.Nil(t, tnt)
	})
}

func TestRPC_CreateTenant(t *testing.T) {
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

	tenant, _ := newTenant(t, enc, issuer)
	dbClient := &dbMock{
		sessions: map[string]*data.Session{},
		tenants:  map[uint64][]*data.Tenant{tenant.ProjectID: {tenant}},
	}
	svc := initRPC(cfg, enc, dbClient)

	srv := httptest.NewServer(svc.Handler())
	defer srv.Close()

	c := proto.NewWaasAuthenticatorAdminClient(srv.URL, http.DefaultClient)
	header := make(http.Header)
	header.Set("Authorization", "Bearer "+adminJWT)
	ctx, err := proto.WithHTTPRequestHeaders(context.Background(), header)

	audience := []string{"audience"}
	validOidcProviders := []*proto.OpenIdProvider{{Issuer: issuer, Audience: audience}}
	allowedOrigins := []string{"http://localhost"}

	t.Run("TenantAlreadyExists", func(t *testing.T) {
		tnt, code, err := c.CreateTenant(ctx, tenant.ProjectID, "WAAS_ACCESS_TOKEN", validOidcProviders, allowedOrigins, nil)
		assert.Nil(t, tnt)
		assert.Empty(t, code)
		assert.ErrorContains(t, err, "tenant already exists")
	})

	t.Run("InvalidProvider", func(t *testing.T) {
		invalidOidcProviders := []*proto.OpenIdProvider{
			{Issuer: issuer, Audience: audience},
			{Issuer: "INVALID", Audience: audience},
		}
		tnt, code, err := c.CreateTenant(ctx, 2, "WAAS_ACCESS_TOKEN", invalidOidcProviders, allowedOrigins, nil)
		assert.Nil(t, tnt)
		assert.Empty(t, code)
		assert.ErrorContains(t, err, "invalid oidcProviders")
	})

	t.Run("InvalidOrigin", func(t *testing.T) {
		invalidOrigins := []string{"localhost"}
		tnt, code, err := c.CreateTenant(ctx, 3, "WAAS_ACCESS_TOKEN", validOidcProviders, invalidOrigins, nil)
		assert.Nil(t, tnt)
		assert.Empty(t, code)
		assert.ErrorContains(t, err, "invalid allowedOrigins")
	})

	t.Run("InvalidPassword", func(t *testing.T) {
		password := "Password123"
		tnt, code, err := c.CreateTenant(ctx, 4, "WAAS_ACCESS_TOKEN", validOidcProviders, allowedOrigins, &password)
		assert.Nil(t, tnt)
		assert.Empty(t, code)
		assert.ErrorContains(t, err, "password must be at least 12 characters long")
	})

	t.Run("Success", func(t *testing.T) {
		tnt, code, err := c.CreateTenant(ctx, 5, "WAAS_ACCESS_TOKEN", validOidcProviders, allowedOrigins, nil)
		require.NoError(t, err)
		assert.NotEmpty(t, code)
		assert.NotNil(t, tnt)

		assert.Equal(t, uint64(5), tnt.ProjectID)

		assert.Contains(t, dbClient.tenants, tnt.ProjectID)
	})

	t.Run("SuccessWithPassword", func(t *testing.T) {
		password := "Password1234"
		tnt, code, err := c.CreateTenant(ctx, 6, "WAAS_ACCESS_TOKEN", validOidcProviders, allowedOrigins, &password)
		require.NoError(t, err)
		assert.Equal(t, password, code)
		assert.NotNil(t, tnt)

		assert.Equal(t, uint64(6), tnt.ProjectID)

		assert.Contains(t, dbClient.tenants, tnt.ProjectID)
	})
}
