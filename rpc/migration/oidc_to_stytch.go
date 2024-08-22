package migration

import (
	"context"
	"errors"
	"fmt"

	"github.com/0xsequence/waas-authenticator/config"
	"github.com/0xsequence/waas-authenticator/data"
	"github.com/0xsequence/waas-authenticator/proto"
	"github.com/0xsequence/waas-authenticator/rpc/attestation"
	"github.com/0xsequence/waas-authenticator/rpc/crypto"
	"github.com/0xsequence/waas-authenticator/rpc/tenant"
)

type OIDCToStytch struct {
	accounts *data.AccountTable
	tenants  *data.TenantTable
	configs  map[uint64]config.OIDCToStytchConfig
}

func (m *OIDCToStytch) OnRegisterSession(ctx context.Context, originalAccount *data.Account) error {
	att := attestation.FromContext(ctx)
	tntData := tenant.FromContext(ctx)

	if originalAccount.ProjectID != tntData.ProjectID {
		return errors.New("project id does not match")
	}
	if originalAccount.Identity.Type != proto.IdentityType_OIDC {
		return nil
	}

	cfg, ok := m.configs[tntData.ProjectID]
	if !ok {
		return nil
	}
	if originalAccount.Identity.Issuer != cfg.FromIssuer {
		return nil
	}

	migratedIdentity := proto.Identity{
		Type:    proto.IdentityType_Stytch,
		Issuer:  cfg.StytchProject,
		Subject: originalAccount.Identity.Subject,
		Email:   originalAccount.Email,
	}
	_, accountFound, err := m.accounts.Get(ctx, tntData.ProjectID, migratedIdentity)
	if err != nil {
		return fmt.Errorf("failed to retrieve account: %w", err)
	}
	if accountFound {
		return nil
	}

	accData := &proto.AccountData{
		ProjectID: tntData.ProjectID,
		UserID:    originalAccount.UserID,
		Identity:  migratedIdentity.String(),
		CreatedAt: originalAccount.CreatedAt,
	}
	encryptedKey, algorithm, ciphertext, err := crypto.EncryptData(ctx, att, tntData.KMSKeys[0], accData)
	if err != nil {
		return fmt.Errorf("encrypting account data: %w", err)
	}

	account := &data.Account{
		ProjectID:          tntData.ProjectID,
		Identity:           data.Identity(migratedIdentity),
		UserID:             accData.UserID,
		Email:              migratedIdentity.Email,
		ProjectScopedEmail: fmt.Sprintf("%d|%s", tntData.ProjectID, migratedIdentity.Email),
		EncryptedKey:       encryptedKey,
		Algorithm:          algorithm,
		Ciphertext:         ciphertext,
		CreatedAt:          accData.CreatedAt,
	}
	if err := m.accounts.Create(ctx, account); err != nil {
		return fmt.Errorf("saving account: %w", err)
	}
	return nil
}

func (m *OIDCToStytch) NextBatch(ctx context.Context, projectID uint64, page data.Page) ([]string, data.Page, error) {
	cfg, ok := m.configs[projectID]
	if !ok {
		return nil, page, fmt.Errorf("project %d not found", projectID)
	}

	items := make([]string, 0, page.Limit)
	for {
		accounts, page, err := m.accounts.ListByProjectAndIdentity(ctx, page, projectID, proto.IdentityType_OIDC, cfg.FromIssuer)
		if err != nil {
			return nil, page, err
		}

		for _, acc := range accounts {
			migratedIdentity := proto.Identity{
				Type:    proto.IdentityType_Stytch,
				Issuer:  cfg.StytchProject,
				Subject: acc.Identity.Subject,
			}
			_, found, err := m.accounts.Get(ctx, acc.ProjectID, migratedIdentity)
			if err != nil {
				return nil, page, err
			}
			if !found {
				items = append(items, acc.Identity.String())
			}
		}

		if len(accounts) < int(page.Limit) || len(items) >= int(page.Limit) {
			return items, page, nil
		}
	}
}

func (m *OIDCToStytch) ProcessItems(ctx context.Context, tenant *proto.TenantData, items []string) (*Result, error) {
	if len(items) > 100 {
		return nil, fmt.Errorf("can only process 100 items at a time")
	}

	att := attestation.FromContext(ctx)
	cfg, ok := m.configs[tenant.ProjectID]
	if !ok {
		return nil, fmt.Errorf("project not configured for migration")
	}

	res := NewResult()

	identities := make([]proto.Identity, len(items))
	for i, item := range items {
		if err := identities[i].FromString(item); err != nil {
			res.Errorf(item, "parsing identity: %w", err)
			continue
		}
		if identities[i].Type != proto.IdentityType_OIDC || identities[i].Issuer != cfg.FromIssuer {
			res.Errorf(item, "incorrect identity: %s", identities[i].String())
			continue
		}
	}

	originalAccounts, err := m.accounts.GetBatch(ctx, tenant.ProjectID, identities)
	if err != nil {
		return nil, fmt.Errorf("getting accounts: %w", err)
	}

	for _, originalAccount := range originalAccounts {
		item := originalAccount.Identity.String()
		migratedIdentity := proto.Identity{
			Type:    proto.IdentityType_Stytch,
			Issuer:  cfg.StytchProject,
			Subject: originalAccount.Identity.Subject,
			Email:   originalAccount.Email,
		}
		accData := &proto.AccountData{
			ProjectID: tenant.ProjectID,
			UserID:    originalAccount.UserID,
			Identity:  migratedIdentity.String(),
			CreatedAt: originalAccount.CreatedAt,
		}
		encryptedKey, algorithm, ciphertext, err := crypto.EncryptData(ctx, att, tenant.KMSKeys[0], accData)
		if err != nil {
			res.Errorf(item, "encrypting account data: %w", err)
			continue
		}

		account := &data.Account{
			ProjectID:          tenant.ProjectID,
			Identity:           data.Identity(migratedIdentity),
			UserID:             accData.UserID,
			Email:              migratedIdentity.Email,
			ProjectScopedEmail: fmt.Sprintf("%d|%s", tenant.ProjectID, migratedIdentity.Email),
			EncryptedKey:       encryptedKey,
			Algorithm:          algorithm,
			Ciphertext:         ciphertext,
			CreatedAt:          accData.CreatedAt,
		}
		if err := m.accounts.Create(ctx, account); err != nil {
			res.Errorf(item, "saving account: %w", err)
			continue
		}

		res.AddItem(item)
	}

	return res, nil
}
