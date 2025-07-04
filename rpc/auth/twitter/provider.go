package twitter

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/0xsequence/ethkit/go-ethereum/common/hexutil"
	ethcrypto "github.com/0xsequence/ethkit/go-ethereum/crypto"
	"github.com/0xsequence/go-sequence/intents"
	"github.com/0xsequence/waas-authenticator/proto"
	"github.com/0xsequence/waas-authenticator/rpc/auth"
	"github.com/0xsequence/waas-authenticator/rpc/tenant"
)

type AuthProvider struct {
	client HTTPClient
}

func NewAuthProvider(client HTTPClient) auth.Provider {
	return &AuthProvider{client: client}
}

func (*AuthProvider) IsEnabled(tenant *proto.TenantData) bool {
	return tenant.AuthConfig.Twitter.Enabled
}

func (p *AuthProvider) ValidateTenant(ctx context.Context, tenant *proto.TenantData) error {
	if tenant.AuthConfig.Twitter.Enabled {
		if strings.TrimSpace(tenant.AuthConfig.Twitter.ClientID) == "" {
			return fmt.Errorf("missing clientID")
		}
	}
	return nil
}

func (p *AuthProvider) InitiateAuth(
	ctx context.Context,
	verifCtx *proto.VerificationContext,
	verifier string,
	sessionID string,
	storeFn auth.StoreVerificationContextFn,
) (*intents.IntentResponseAuthInitiated, error) {
	tnt := tenant.FromContext(ctx)

	if verifCtx != nil {
		return nil, fmt.Errorf("cannot reuse an old proof")
	}

	verifCtx = &proto.VerificationContext{
		ProjectID:    tnt.ProjectID,
		SessionID:    sessionID,
		IdentityType: proto.IdentityType_Twitter,
		Verifier:     verifier,
		Answer:       &verifier,
		ExpiresAt:    time.Now().Add(24 * time.Hour),
	}
	if err := storeFn(ctx, verifCtx); err != nil {
		return nil, err
	}

	res := &intents.IntentResponseAuthInitiated{
		SessionID:    verifCtx.SessionID,
		IdentityType: intents.IdentityType_Twitter,
		ExpiresIn:    int(verifCtx.ExpiresAt.Sub(time.Now()).Seconds()),
	}
	return res, nil
}

func (p *AuthProvider) Verify(
	ctx context.Context,
	verifCtx *proto.VerificationContext,
	sessionID string,
	answer string,
) (proto.Identity, error) {
	if verifCtx == nil || verifCtx.Answer == nil {
		return proto.Identity{}, fmt.Errorf("verification context not found")
	}

	expectedHash := hexutil.Encode(ethcrypto.Keccak256([]byte(answer)))
	if *verifCtx.Answer != expectedHash {
		return proto.Identity{}, fmt.Errorf("invalid token hash")
	}

	accInfo, err := getUser(ctx, answer, p.client)
	if err != nil {
		return proto.Identity{}, fmt.Errorf("failed to get X user info: %w", err)
	}

	identity := proto.Identity{
		Type:    proto.IdentityType_Twitter,
		Issuer:  "",
		Subject: accInfo.ID,
		Email:   accInfo.Email,
	}
	return identity, nil
}
