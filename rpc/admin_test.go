package rpc_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/0xsequence/waas-authenticator/proto"
	"github.com/goware/validation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const adminJWT = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJoZWxsbyI6IndvcmxkIn0.etvI60-iOY2f9a3d1SBYmbrDllxcYm0rF8tB5YyUWwFMBSArAFG8a6ms1k3OtR9xe8uLTeeOC80eLOMWSUgQd_TZmu5RPNBYMMhcqWnl5H64chO2sFrRDdxUCnNYRccEnDesQACmqaf1bbDCFs8Hwh2O4_rHoscuJ7kb3XBCC2a52Dyh8EYTEXg8DJGmUFQX5XKKb35uurejcKo_5yK2onr26SVm_arl4CCcDeNITv1mP1aGvroj1PUVGTpnd9mScPAoecmihdiMMF9VdXU3KGNvK-l44Miq9-a9mnwOwZNtoxqQxlh-cmcNAV5cGh66zfbPnWKb9t9YrMY4wKtshg"

func TestRPC_GetTenant(t *testing.T) {
	issuer, _, closeJWKS := issueAccessTokenAndRunJwksServer(t)
	defer closeJWKS()

	svc := initRPC(t)

	tenant, _ := newTenant(t, svc.Enclave, issuer)
	tenant2, _ := newTenantWithAuthConfig(t, svc.Enclave, proto.AuthConfig{Email: proto.AuthEmailConfig{Enabled: true}})
	require.NoError(t, svc.Tenants.Add(context.Background(), tenant))
	require.NoError(t, svc.Tenants.Add(context.Background(), tenant2))

	srv := httptest.NewServer(svc.Handler())
	defer srv.Close()

	c := proto.NewWaasAuthenticatorAdminClient(srv.URL, http.DefaultClient)
	header := make(http.Header)
	header.Set("Authorization", "Bearer "+adminJWT)
	ctx, err := proto.WithHTTPRequestHeaders(context.Background(), header)
	require.NoError(t, err)

	t.Run("ExistingTenant", func(t *testing.T) {
		tnt, err := c.GetTenant(ctx, tenant.ProjectID)
		require.NoError(t, err)
		assert.NotEmpty(t, tnt)
		assert.Equal(t, tenant.ProjectID, tnt.ProjectID)
		assert.Equal(t, validation.Origins{"http://localhost"}, tnt.AllowedOrigins)
	})

	t.Run("ExistingTenantWithAuthConfig", func(t *testing.T) {
		tnt, err := c.GetTenant(ctx, tenant2.ProjectID)
		require.NoError(t, err)
		assert.NotEmpty(t, tnt)
		assert.Equal(t, tenant2.ProjectID, tnt.ProjectID)
		assert.True(t, tnt.AuthConfig.Email.Enabled)
	})

	t.Run("MissingTenant", func(t *testing.T) {
		tnt, err := c.GetTenant(ctx, 12345)
		assert.ErrorIs(t, err, proto.ErrTenantNotFound)
		assert.Nil(t, tnt)
	})
}

func TestRPC_CreateTenant(t *testing.T) {
	issuer, _, closeJWKS := issueAccessTokenAndRunJwksServer(t)
	defer closeJWKS()

	svc := initRPC(t)

	tenant, _ := newTenant(t, svc.Enclave, issuer)
	require.NoError(t, svc.Tenants.Add(context.Background(), tenant))

	srv := httptest.NewServer(svc.Handler())
	defer srv.Close()

	c := proto.NewWaasAuthenticatorAdminClient(srv.URL, http.DefaultClient)
	header := make(http.Header)
	header.Set("Authorization", "Bearer "+adminJWT)
	ctx, err := proto.WithHTTPRequestHeaders(context.Background(), header)
	require.NoError(t, err)

	audience := []string{"audience"}
	validOidcProviders := []*proto.OpenIdProvider{{Issuer: issuer, Audience: audience}}
	allowedOrigins := []string{"http://localhost"}

	t.Run("TenantAlreadyExists", func(t *testing.T) {
		tnt, code, err := c.CreateTenant(ctx, tenant.ProjectID, "WAAS_ACCESS_TOKEN", nil, validOidcProviders, allowedOrigins, nil)
		assert.Nil(t, tnt)
		assert.Empty(t, code)
		assert.ErrorContains(t, err, "tenant already exists")
	})

	t.Run("InvalidProvider", func(t *testing.T) {
		invalidOidcProviders := []*proto.OpenIdProvider{
			{Issuer: issuer, Audience: audience},
			{Issuer: "INVALID", Audience: audience},
		}
		tnt, code, err := c.CreateTenant(ctx, currentProjectID.Add(1), "WAAS_ACCESS_TOKEN", nil, invalidOidcProviders, allowedOrigins, nil)
		assert.Nil(t, tnt)
		assert.Empty(t, code)
		assert.ErrorContains(t, err, "invalid auth provider configuration")
	})

	t.Run("InvalidOrigin", func(t *testing.T) {
		invalidOrigins := []string{"localhost"}
		tnt, code, err := c.CreateTenant(ctx, currentProjectID.Add(1), "WAAS_ACCESS_TOKEN", nil, validOidcProviders, invalidOrigins, nil)
		assert.Nil(t, tnt)
		assert.Empty(t, code)
		assert.ErrorContains(t, err, "invalid allowedOrigins")
	})

	t.Run("InvalidPassword", func(t *testing.T) {
		password := "Password123"
		tnt, code, err := c.CreateTenant(ctx, currentProjectID.Add(1), "WAAS_ACCESS_TOKEN", nil, validOidcProviders, allowedOrigins, &password)
		assert.Nil(t, tnt)
		assert.Empty(t, code)
		assert.ErrorContains(t, err, "password must be at least 12 characters long")
	})

	t.Run("Success", func(t *testing.T) {
		projectID := currentProjectID.Add(1)
		tnt, code, err := c.CreateTenant(ctx, projectID, "WAAS_ACCESS_TOKEN", nil, validOidcProviders, allowedOrigins, nil)
		require.NoError(t, err)
		assert.NotEmpty(t, code)
		assert.NotNil(t, tnt)

		assert.Equal(t, projectID, tnt.ProjectID)

		//assert.Contains(t, dbClient.tenants, tnt.ProjectID)
	})

	t.Run("SuccessWithPassword", func(t *testing.T) {
		projectID := currentProjectID.Add(1)
		password := "Password1234"
		tnt, code, err := c.CreateTenant(ctx, projectID, "WAAS_ACCESS_TOKEN", nil, validOidcProviders, allowedOrigins, &password)
		require.NoError(t, err)
		assert.Equal(t, password, code)
		assert.NotNil(t, tnt)

		assert.Equal(t, projectID, tnt.ProjectID)

		//assert.Contains(t, dbClient.tenants, tnt.ProjectID)
	})
}
