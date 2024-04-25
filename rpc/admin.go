package rpc

import (
	"context"
	"encoding/base32"
	"fmt"
	"time"

	"github.com/0xsequence/ethkit/ethwallet"
	"github.com/0xsequence/ethkit/go-ethereum/common"
	"github.com/0xsequence/ethkit/go-ethereum/common/hexutil"
	"github.com/0xsequence/waas-authenticator/data"
	"github.com/0xsequence/waas-authenticator/proto"
	"github.com/0xsequence/waas-authenticator/rpc/attestation"
	"github.com/0xsequence/waas-authenticator/rpc/crypto"
	"github.com/goware/validation"
	"golang.org/x/sync/errgroup"
)

func (s *RPC) GetTenant(ctx context.Context, projectID uint64) (*proto.Tenant, error) {
	tnt, _, err := s.Tenants.GetLatest(ctx, projectID)
	if err != nil {
		return nil, err
	}
	if tnt == nil {
		return nil, proto.ErrTenantNotFound
	}

	tenantData, _, err := crypto.DecryptData[*proto.TenantData](ctx, tnt.EncryptedKey, tnt.Ciphertext, s.Config.KMS.TenantKeys)
	if err != nil {
		return nil, fmt.Errorf("decrypt tenant data: %w", err)
	}

	retTenant := &proto.Tenant{
		ProjectID:      tnt.ProjectID,
		Version:        tnt.Version,
		OIDCProviders:  tenantData.OIDCProviders,
		AllowedOrigins: tenantData.AllowedOrigins,
		UpdatedAt:      tnt.CreatedAt,
	}
	return retTenant, nil
}

func (s *RPC) CreateTenant(
	ctx context.Context,
	projectID uint64,
	waasAccessToken string,
	oidcProviders []*proto.OpenIdProvider,
	allowedOrigins []string,
	password *string,
) (*proto.Tenant, string, error) {
	att := attestation.FromContext(ctx)

	_, found, err := s.Tenants.GetLatest(ctx, projectID)
	if err != nil {
		return nil, "", fmt.Errorf("get latest tenant version: %w", err)
	}
	if found {
		return nil, "", fmt.Errorf("tenant already exists")
	}

	if err := s.validateOIDCProviders(ctx, oidcProviders); err != nil {
		return nil, "", fmt.Errorf("invalid oidcProviders: %w", err)
	}

	origins, err := validation.NewOrigins(allowedOrigins...)
	if err != nil {
		return nil, "", fmt.Errorf("invalid allowedOrigins: %w", err)
	}

	wallet, err := ethwallet.NewWalletFromRandomEntropy()
	if err != nil {
		return nil, "", fmt.Errorf("generating wallet: %w", err)
	}

	waasCtx := waasContext(ctx, waasAccessToken)

	// TODO: these are 4 calls to WaaS API, can we do it all in one call?
	if _, err := s.Wallets.UseHotWallet(waasCtx, wallet.Address().String()); err != nil {
		return nil, "", fmt.Errorf("using hot wallet: %w", err)
	}

	userSalt, err := s.Wallets.UserSalt(waasCtx)
	if err != nil {
		return nil, "", fmt.Errorf("retrieving user salt: %w", err)
	}
	userSaltBytes, err := hexutil.Decode(userSalt)
	if err != nil {
		return nil, "", fmt.Errorf("decoding user salt: %w", err)
	}

	parentAddress, err := s.Wallets.ProjectWallet(waasCtx)
	if err != nil {
		return nil, "", fmt.Errorf("retrieving parent wallet: %w", err)
	}

	seqContext, err := s.Wallets.SequenceContext(waasCtx)
	if err != nil {
		return nil, "", fmt.Errorf("retrieving Sequence context: %w", err)
	}

	var upgradeCode string
	if password != nil {
		if len(*password) < 12 {
			return nil, "", fmt.Errorf("password must be at least 12 characters long")
		}
		upgradeCode = *password
	} else {
		b := make([]byte, 10)
		if _, err := att.Read(b); err != nil {
			return nil, "", fmt.Errorf("reading attestation: %w", err)
		}
		upgradeCode = base32.StdEncoding.EncodeToString(b)
	}

	privateKey := wallet.PrivateKeyHex()[2:] // remove 0x prefix
	tenantData := proto.TenantData{
		ProjectID:     projectID,
		PrivateKey:    privateKey,
		ParentAddress: common.HexToAddress(parentAddress),
		UserSalt:      userSaltBytes,
		SequenceContext: &proto.MiniSequenceContext{
			Factory:    seqContext.Factory,
			MainModule: seqContext.MainModule,
		},
		UpgradeCode:     upgradeCode,
		WaasAccessToken: waasAccessToken,
		OIDCProviders:   oidcProviders,
		KMSKeys:         s.Config.KMS.DefaultSessionKeys,
		AllowedOrigins:  origins,
	}

	encryptedKey, algorithm, ciphertext, err := crypto.EncryptData(ctx, att, s.Config.KMS.TenantKeys[0], tenantData)
	if err != nil {
		return nil, "", fmt.Errorf("encrypting tenant data: %w", err)
	}

	dbTenant := &data.Tenant{
		ProjectID:    projectID,
		Version:      1,
		EncryptedKey: encryptedKey,
		Algorithm:    algorithm,
		Ciphertext:   ciphertext,
		CreatedAt:    time.Now(),
	}
	if err := s.Tenants.Add(ctx, dbTenant); err != nil {
		return nil, "", fmt.Errorf("storing tenant: %w", err)
	}

	retTenant := &proto.Tenant{
		ProjectID:      projectID,
		Version:        dbTenant.Version,
		OIDCProviders:  tenantData.OIDCProviders,
		AllowedOrigins: tenantData.AllowedOrigins,
		UpdatedAt:      dbTenant.CreatedAt,
	}
	return retTenant, tenantData.UpgradeCode, nil
}

func (s *RPC) UpdateTenant(
	ctx context.Context, projectID uint64, upgradeCode string, oidcProviders []*proto.OpenIdProvider, allowedOrigins []string,
) (*proto.Tenant, error) {
	att := attestation.FromContext(ctx)

	tnt, found, err := s.Tenants.GetLatest(ctx, projectID)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, proto.ErrTenantNotFound
	}

	tntData, _, err := crypto.DecryptData[*proto.TenantData](ctx, tnt.EncryptedKey, tnt.Ciphertext, s.Config.KMS.TenantKeys)
	if err != nil {
		return nil, fmt.Errorf("decrypt tenant data: %w", err)
	}

	// TODO: this should be an input in a form hosted by the authenticator.
	if tntData.UpgradeCode != upgradeCode {
		return nil, fmt.Errorf("invalid upgrade code")
	}

	if err := s.validateOIDCProviders(ctx, oidcProviders); err != nil {
		return nil, fmt.Errorf("invalid oidcProviders: %w", err)
	}

	origins, err := validation.NewOrigins(allowedOrigins...)
	if err != nil {
		return nil, fmt.Errorf("invalid allowedOrigins: %w", err)
	}

	tntData.OIDCProviders = oidcProviders
	tntData.AllowedOrigins = origins

	encryptedKey, algorithm, ciphertext, err := crypto.EncryptData(ctx, att, s.Config.KMS.TenantKeys[0], tntData)
	if err != nil {
		return nil, fmt.Errorf("encrypting tenant data: %w", err)
	}

	tnt.Version += 1
	tnt.EncryptedKey = encryptedKey
	tnt.Ciphertext = ciphertext
	tnt.Algorithm = algorithm

	if err := s.Tenants.Add(ctx, tnt); err != nil {
		return nil, err
	}

	retTenant := &proto.Tenant{
		ProjectID:      tnt.ProjectID,
		Version:        tnt.Version,
		OIDCProviders:  tntData.OIDCProviders,
		AllowedOrigins: tntData.AllowedOrigins,
		UpdatedAt:      tnt.CreatedAt,
	}
	return retTenant, nil
}

func (s *RPC) validateOIDCProviders(ctx context.Context, providers []*proto.OpenIdProvider) error {
	var wg errgroup.Group
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for i, provider := range providers {
		provider := provider

		if provider.Issuer == "" {
			return fmt.Errorf("provider %d: empty issuer", i)
		}

		if len(provider.Audience) < 1 {
			return fmt.Errorf("provider %d: at least one audience is required", i)
		}

		wg.Go(func() error {
			if _, err := s.Verifier.GetKeySet(ctx, provider.Issuer); err != nil {
				return err
			}
			return nil
		})
	}

	return wg.Wait()
}
