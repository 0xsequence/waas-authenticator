package rpc

import (
	"context"
	"fmt"

	"github.com/0xsequence/waas-authenticator/data"
	"github.com/0xsequence/waas-authenticator/proto"
	"github.com/0xsequence/waas-authenticator/rpc/crypto"
)

func (s *RPC) NextMigrationBatch(ctx context.Context, migration proto.Migration, projectId uint64, page *proto.Page) (*proto.Page, []string, error) {
	m, err := s.Migrations.Get(migration)
	if err != nil {
		return nil, nil, fmt.Errorf("get migration: %w", err)
	}

	dbPage, err := data.PageFromProto(page)
	if err != nil {
		return nil, nil, fmt.Errorf("get page from proto: %w", err)
	}

	items, dbPage, err := m.NextBatch(ctx, projectId, dbPage)
	if err != nil {
		return nil, nil, fmt.Errorf("get next batch: %w", err)
	}

	page, err = dbPage.ToProto()
	if err != nil {
		return nil, nil, fmt.Errorf("convert db page to proto: %w", err)
	}

	return page, items, nil
}

func (s *RPC) ProcessMigrationBatch(ctx context.Context, migration proto.Migration, projectID uint64, items []string) (map[string][]string, map[string]string, error) {
	m, err := s.Migrations.Get(migration)
	if err != nil {
		return nil, nil, err
	}

	tenant, found, err := s.Tenants.GetLatest(ctx, projectID)
	if err != nil {
		return nil, nil, fmt.Errorf("could not retrieve tenant: %w", err)
	}
	if !found {
		return nil, nil, fmt.Errorf("invalid tenant: %v", projectID)
	}

	tntData, _, err := crypto.DecryptData[*proto.TenantData](ctx, tenant.EncryptedKey, tenant.Ciphertext, s.Config.KMS.TenantKeys)
	if err != nil {
		return nil, nil, fmt.Errorf("could not decrypt tenant data: %v", projectID)
	}

	res, err := m.ProcessItems(ctx, tntData, items)
	if err != nil {
		return nil, nil, fmt.Errorf("could not process items: %w", err)
	}

	itemErrors := make(map[string]string)
	for item, err := range res.Errors {
		itemErrors[item] = err.Error()
	}

	return res.Logs, itemErrors, nil
}
