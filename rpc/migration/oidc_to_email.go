package migration

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/0xsequence/waas-authenticator/config"
	"github.com/0xsequence/waas-authenticator/data"
	"github.com/0xsequence/waas-authenticator/proto"
	"github.com/0xsequence/waas-authenticator/rpc/attestation"
	"github.com/0xsequence/waas-authenticator/rpc/auth/email"
	"github.com/0xsequence/waas-authenticator/rpc/crypto"
	"github.com/0xsequence/waas-authenticator/rpc/tenant"
)

type OIDCToEmail struct {
	accounts *data.AccountTable
	tenants  *data.TenantTable
	config   config.EmailMigrationConfig
}

func (m *OIDCToEmail) OnRegisterSession(ctx context.Context, originalAccount *data.Account) error {
	att := attestation.FromContext(ctx)
	tntData := tenant.FromContext(ctx)

	if originalAccount.ProjectID != tntData.ProjectID {
		return errors.New("project id does not match")
	}
	if !slices.Contains(m.config.Projects, originalAccount.ProjectID) {
		return nil
	}
	if originalAccount.Identity.Type != proto.IdentityType_OIDC {
		return nil
	}
	if !strings.HasPrefix(originalAccount.Identity.Issuer, m.config.IssuerPrefix) {
		return nil
	}

	normEmail := email.Normalize(originalAccount.Email)
	migratedIdentity := proto.Identity{
		Type:    proto.IdentityType_Email,
		Subject: normEmail,
		Email:   normEmail,
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

func (m *OIDCToEmail) NextBatch(ctx context.Context, projectID uint64, page data.Page) ([]string, data.Page, error) {
	if !slices.Contains(m.config.Projects, projectID) {
		return nil, data.Page{}, fmt.Errorf("project id does not match")
	}

	items := make([]string, 0, page.Limit)
	for {
		accounts, page, err := m.accounts.ListByProjectAndIdentity(ctx, page, projectID, proto.IdentityType_OIDC, m.config.IssuerPrefix)
		if err != nil {
			return nil, page, err
		}

		for _, acc := range accounts {
			normEmail := email.Normalize(acc.Email)
			migratedIdentity := proto.Identity{
				Type:    proto.IdentityType_Email,
				Subject: normEmail,
				Email:   normEmail,
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

func (m *OIDCToEmail) ProcessItems(ctx context.Context, tenant *proto.TenantData, items []string) (*Result, error) {
	if !slices.Contains(m.config.Projects, tenant.ProjectID) {
		return nil, fmt.Errorf("project id does not match")
	}

	if len(items) > 100 {
		return nil, fmt.Errorf("can only process 100 items at a time")
	}

	att := attestation.FromContext(ctx)
	res := NewResult()

	identities := make([]proto.Identity, len(items))
	for i, item := range items {
		if err := identities[i].FromString(item); err != nil {
			res.Errorf(item, "parsing identity: %w", err)
			continue
		}
		if identities[i].Type != proto.IdentityType_OIDC || !strings.HasPrefix(identities[i].Issuer, m.config.IssuerPrefix) {
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
		normEmail := email.Normalize(originalAccount.Email)
		migratedIdentity := proto.Identity{
			Type:    proto.IdentityType_Email,
			Subject: normEmail,
			Email:   normEmail,
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
