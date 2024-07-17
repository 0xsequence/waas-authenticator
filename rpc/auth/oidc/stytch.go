package oidc

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
	"github.com/0xsequence/waas-authenticator/rpc/tracing"
	"github.com/goware/cachestore"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type StytchAuthProvider struct {
	*AuthProvider
}

func NewStytchAuthProvider(cacheBackend cachestore.Backend, client HTTPClient) (auth.Provider, error) {
	p, err := NewAuthProvider(cacheBackend, client)
	if err != nil {
		return nil, err
	}
	return &StytchAuthProvider{AuthProvider: p.(*AuthProvider)}, nil
}

func (*StytchAuthProvider) IsEnabled(tenant *proto.TenantData) bool {
	return tenant.AuthConfig.Stytch.Enabled
}

func (p *StytchAuthProvider) InitiateAuth(
	ctx context.Context,
	verifCtx *proto.VerificationContext,
	verifier string,
	sessionID string,
	storeFn auth.StoreVerificationContextFn,
) (*intents.IntentResponseAuthInitiated, error) {
	tnt := tenant.FromContext(ctx)

	if verifCtx != nil {
		return nil, fmt.Errorf("cannot reuse an old ID token")
	}

	verifCtx, err := p.constructVerificationContext(proto.IdentityType_Stytch, tnt.ProjectID, sessionID, verifier)
	if err != nil {
		return nil, err
	}
	if err := storeFn(ctx, verifCtx); err != nil {
		return nil, err
	}

	res := &intents.IntentResponseAuthInitiated{
		SessionID:    verifCtx.SessionID,
		IdentityType: intents.IdentityType_Stytch,
		ExpiresIn:    int(verifCtx.ExpiresAt.Sub(time.Now()).Seconds()),
	}
	return res, nil
}

func (p *StytchAuthProvider) Verify(
	ctx context.Context, verifCtx *proto.VerificationContext, sessionID string, answer string,
) (ident proto.Identity, err error) {
	tnt := tenant.FromContext(ctx)
	stytchProjectID := tnt.AuthConfig.Stytch.ProjectID

	if verifCtx == nil {
		return proto.Identity{}, fmt.Errorf("auth session not found")
	}

	tok, err := jwt.Parse([]byte(answer), jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return proto.Identity{}, fmt.Errorf("parse JWT: %w", err)
	}

	expectedHash := hexutil.Encode(ethcrypto.Keccak256([]byte(answer)))
	if *verifCtx.Answer != expectedHash {
		return proto.Identity{}, fmt.Errorf("invalid token hash")
	}

	if err := p.verifyChallenge(tok, *verifCtx.Challenge); err != nil {
		return proto.Identity{}, fmt.Errorf("verify challenge: %w", err)
	}

	ks := &operationKeySet{
		ctx:       ctx,
		iss:       p.getJWKSURL(stytchProjectID),
		store:     p.store,
		getKeySet: p.GetKeySet,
	}

	if _, err := jws.Verify([]byte(answer), jws.WithKeySet(ks, jws.WithMultipleKeysPerKeyID(false))); err != nil {
		return proto.Identity{}, fmt.Errorf("signature verification: %w", err)
	}

	validateOptions := []jwt.ValidateOption{
		jwt.WithValidator(withIssuer("stytch.com/"+stytchProjectID, false)),
		jwt.WithAcceptableSkew(10 * time.Second),
		jwt.WithValidator(withAudience([]string{stytchProjectID})),
	}

	if err := jwt.Validate(tok, validateOptions...); err != nil {
		return proto.Identity{}, fmt.Errorf("JWT validation: %w", err)
	}

	identity := proto.Identity{
		Type:    proto.IdentityType_Stytch,
		Issuer:  stytchProjectID,
		Subject: tok.Subject(),
		Email:   p.getEmailFromToken(tok),
	}
	return identity, nil
}

func (p *StytchAuthProvider) GetKeySet(ctx context.Context, jwksURL string) (set jwk.Set, err error) {
	keySet, err := jwk.Fetch(ctx, jwksURL, jwk.WithHTTPClient(tracing.WrapClientWithContext(ctx, p.client)))
	if err != nil {
		return nil, fmt.Errorf("fetch issuer keys: %w", err)
	}
	return keySet, nil
}

func (p *StytchAuthProvider) getJWKSURL(stytchProjectID string) string {
	if strings.HasPrefix(stytchProjectID, "project-test-") {
		return "https://test.stytch.com/v1/sessions/jwks/" + stytchProjectID
	}
	return "https://api.stytch.com/v1/sessions/jwks/" + stytchProjectID
}

func (p *StytchAuthProvider) getEmailFromToken(tok jwt.Token) string {
	session, ok := tok.Get("https://stytch.com/session")
	if !ok {
		return ""
	}
	sessionMap, ok := session.(map[string]any)
	if !ok {
		return ""
	}
	authFactors, ok := sessionMap["auth_factors"].([]map[string]any)
	if !ok || len(authFactors) == 0 {
		return ""
	}
	for _, authFactor := range authFactors {
		emailFactor, ok := authFactor["email_factor"].(map[string]any)
		if !ok {
			continue
		}
		emailAddress, ok := emailFactor["email_address"].(string)
		if !ok {
			continue
		}
		return emailAddress
	}
	return ""
}
