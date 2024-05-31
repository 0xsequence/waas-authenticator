package auth

import (
	"context"

	"github.com/0xsequence/go-sequence/intents"
	"github.com/0xsequence/waas-authenticator/proto"
	"github.com/0xsequence/waas-authenticator/rpc/tracing"
)

type tracedProvider struct {
	name string
	Provider
}

func NewTracedProvider(name string, provider Provider) Provider {
	return tracedProvider{name: name, Provider: provider}
}

func (p tracedProvider) InitiateAuth(
	ctx context.Context,
	verifCtx *proto.VerificationContext,
	verifier string,
	intent *intents.Intent,
	storeFn StoreVerificationContextFn,
) (*intents.IntentResponseAuthInitiated, error) {
	ctx, span := tracing.Span(ctx, p.name+".InitiateAuth")
	defer span.End()

	res, err := p.Provider.InitiateAuth(ctx, verifCtx, verifier, intent, storeFn)
	if err != nil {
		span.RecordError(err)
	}
	return res, err
}

func (p tracedProvider) Verify(
	ctx context.Context, verifCtx *proto.VerificationContext, sessionID string, answer string,
) (proto.Identity, error) {
	ctx, span := tracing.Span(ctx, p.name+".Verify")
	defer span.End()

	res, err := p.Provider.Verify(ctx, verifCtx, sessionID, answer)
	if err != nil {
		span.RecordError(err)
	}
	return res, err
}

func (p tracedProvider) ValidateTenant(ctx context.Context, tenant *proto.TenantData) error {
	ctx, span := tracing.Span(ctx, p.name+".ValidateTenant")
	defer span.End()

	err := p.Provider.ValidateTenant(ctx, tenant)
	if err != nil {
		span.RecordError(err)
	}
	return err
}
