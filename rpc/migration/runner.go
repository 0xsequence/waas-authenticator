package migration

import (
	"context"
	"fmt"

	"github.com/0xsequence/waas-authenticator/config"
	"github.com/0xsequence/waas-authenticator/data"
	"github.com/0xsequence/waas-authenticator/proto"
)

type Migration interface {
	OnRegisterSession(ctx context.Context, account *data.Account) error
	NextBatch(ctx context.Context, projectID uint64, page data.Page) ([]string, data.Page, error)
	ProcessItems(ctx context.Context, tenant *proto.TenantData, items []string) (*Result, error)
}

type Runner struct {
	migrations map[proto.Migration]Migration
}

func NewRunner(cfg config.MigrationsConfig, accounts *data.AccountTable) *Runner {
	r := &Runner{
		migrations: make(map[proto.Migration]Migration),
	}
	if len(cfg.OIDCToStytch) > 0 {
		m := &OIDCToStytch{
			accounts: accounts,
			configs:  make(map[uint64]config.OIDCToStytchConfig),
		}
		for _, mCfg := range cfg.OIDCToStytch {
			m.configs[mCfg.ProjectID] = mCfg
		}
		r.migrations[proto.Migration_OIDCToStytch] = m
	}
	return r
}

func (r *Runner) OnRegisterSession(ctx context.Context, account *data.Account) error {
	for _, m := range r.migrations {
		if err := m.OnRegisterSession(ctx, account); err != nil {
			return err
		}
	}
	return nil
}

func (r *Runner) Get(migration proto.Migration) (Migration, error) {
	m, ok := r.migrations[migration]
	if !ok {
		return nil, fmt.Errorf("no migration found for %s", migration)
	}
	return m, nil
}
