package oidc

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
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
	"github.com/goware/cachestore/cachestorectl"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"golang.org/x/sync/errgroup"
)

type AuthProvider struct {
	client HTTPClient
	store  cachestore.Store[jwk.Key]
}

func NewAuthProvider(cacheBackend cachestore.Backend, client HTTPClient) (auth.Provider, error) {
	if client == nil {
		client = http.DefaultClient
	}
	store, err := cachestorectl.Open[jwk.Key](cacheBackend)
	if err != nil {
		return nil, err
	}
	return &AuthProvider{
		client: client,
		store:  store,
	}, nil
}

func (*AuthProvider) IsEnabled(tenant *proto.TenantData) bool {
	return len(tenant.OIDCProviders) > 0
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
		return nil, fmt.Errorf("cannot reuse an old ID token")
	}

	verifCtx, err := p.constructVerificationContext(proto.IdentityType_OIDC, tnt.ProjectID, sessionID, verifier)
	if err != nil {
		return nil, err
	}
	if err := storeFn(ctx, verifCtx); err != nil {
		return nil, err
	}

	res := &intents.IntentResponseAuthInitiated{
		SessionID:    verifCtx.SessionID,
		IdentityType: intents.IdentityType_OIDC,
		ExpiresIn:    int(verifCtx.ExpiresAt.Sub(time.Now()).Seconds()),
	}
	return res, nil
}

func (p *AuthProvider) Verify(ctx context.Context, verifCtx *proto.VerificationContext, sessionID string, answer string) (ident proto.Identity, err error) {
	if verifCtx == nil {
		return proto.Identity{}, fmt.Errorf("auth session not found")
	}

	tok, err := jwt.Parse([]byte(answer), jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return proto.Identity{}, fmt.Errorf("parse JWT: %w", err)
	}

	issuer := normalizeIssuer(tok.Issuer())
	idp := getOIDCProvider(ctx, issuer)
	if idp == nil {
		return proto.Identity{}, fmt.Errorf("issuer %q not valid for this tenant", issuer)
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
		iss:       issuer,
		store:     p.store,
		getKeySet: p.GetKeySet,
	}

	if _, err := jws.Verify([]byte(answer), jws.WithKeySet(ks, jws.WithMultipleKeysPerKeyID(false))); err != nil {
		return proto.Identity{}, fmt.Errorf("signature verification: %w", err)
	}

	validateOptions := []jwt.ValidateOption{
		jwt.WithValidator(withIssuer(idp.Issuer, true)),
		jwt.WithAcceptableSkew(10 * time.Second),
		jwt.WithValidator(withAudience(idp.Audience)),
	}

	if err := jwt.Validate(tok, validateOptions...); err != nil {
		return proto.Identity{}, fmt.Errorf("JWT validation: %w", err)
	}

	identity := proto.Identity{
		Type:    proto.IdentityType_OIDC,
		Issuer:  issuer,
		Subject: tok.Subject(),
		Email:   getEmailFromToken(tok),
	}
	return identity, nil
}

func (p *AuthProvider) ValidateTenant(ctx context.Context, tenant *proto.TenantData) error {
	var wg errgroup.Group
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for i, provider := range tenant.OIDCProviders {
		provider := provider

		if provider.Issuer == "" {
			return fmt.Errorf("provider %d: empty issuer", i)
		}

		if len(provider.Audience) < 1 {
			return fmt.Errorf("provider %d: at least one audience is required", i)
		}

		wg.Go(func() error {
			if _, err := p.GetKeySet(ctx, provider.Issuer); err != nil {
				return err
			}
			return nil
		})
	}

	return wg.Wait()
}

func (p *AuthProvider) GetKeySet(ctx context.Context, issuer string) (set jwk.Set, err error) {
	jwksURL, err := fetchJWKSURL(ctx, p.client, issuer)
	if err != nil {
		return nil, fmt.Errorf("fetch issuer keys: %w", err)
	}

	keySet, err := jwk.Fetch(ctx, jwksURL, jwk.WithHTTPClient(tracing.WrapClientWithContext(ctx, p.client)))
	if err != nil {
		return nil, fmt.Errorf("fetch issuer keys: %w", err)
	}
	return keySet, nil
}

func (p *AuthProvider) constructVerificationContext(
	identityType proto.IdentityType, projectID uint64, sessionID string, verifier string,
) (*proto.VerificationContext, error) {
	tokHash, expiresAt, err := p.extractVerifier(verifier)
	if err != nil {
		return nil, err
	}

	if time.Now().After(expiresAt) {
		return nil, fmt.Errorf("token expired")
	}

	answer := tokHash
	challenge := fmt.Sprintf("exp=%d", expiresAt.Unix())

	verifCtx := &proto.VerificationContext{
		ProjectID:    projectID,
		SessionID:    sessionID,
		IdentityType: identityType,
		Verifier:     verifier,
		Answer:       &answer,
		Challenge:    &challenge,
		ExpiresAt:    expiresAt,
	}
	return verifCtx, nil
}

func (p *AuthProvider) extractVerifier(verifier string) (tokHash string, expiresAt time.Time, err error) {
	parts := strings.SplitN(verifier, ";", 2)

	tokHash = parts[0]
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("parse exp: %w", err)
	}
	expiresAt = time.Unix(exp, 0)

	return tokHash, expiresAt, nil
}

func (p *AuthProvider) verifyChallenge(tok jwt.Token, challenge string) error {
	s := strings.TrimPrefix(challenge, "exp=")
	exp, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return fmt.Errorf("parse exp: %w", err)
	}
	expiresAt := time.Unix(exp, 0)

	if !tok.Expiration().Equal(expiresAt) {
		return fmt.Errorf("invalid exp claim")
	}

	return nil
}
