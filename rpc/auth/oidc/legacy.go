package oidc

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/0xsequence/ethkit/ethcoder"
	"github.com/0xsequence/go-sequence/intents"
	"github.com/0xsequence/waas-authenticator/proto"
	"github.com/0xsequence/waas-authenticator/rpc/auth"
	"github.com/0xsequence/waas-authenticator/rpc/tracing"
	"github.com/goware/cachestore"
	"github.com/goware/cachestore/cachestorectl"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"golang.org/x/sync/errgroup"
)

type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
	Get(string) (*http.Response, error)
}

// LegacyAuthProvider is triggered when the openSession intent doesn't specify an explicit identityType as legacy clients
// will. However, it handles identities of type OIDC. It's a one-step flow, without using initiateAuth, the clients are
// expected to call openSession directly. Because of this, LegacyAuthProvider puts an additional requirement on the ID
// tokens passed to it: they must contain the `nonce` or `sequence:session_hash` claim equal to the hash of the session
// the client attempts to open.
type LegacyAuthProvider struct {
	client HTTPClient
	store  cachestore.Store[jwk.Key]
}

func NewLegacyAuthProvider(cacheBackend cachestore.Backend, client HTTPClient) (auth.Provider, error) {
	if client == nil {
		client = http.DefaultClient
	}
	store, err := cachestorectl.Open[jwk.Key](cacheBackend)
	if err != nil {
		return nil, err
	}
	return &LegacyAuthProvider{
		client: client,
		store:  store,
	}, nil
}

func (*LegacyAuthProvider) IsEnabled(tenant *proto.TenantData) bool {
	return len(tenant.OIDCProviders) > 0
}

// InitiateAuth returns an error in the legacy flow.
func (p *LegacyAuthProvider) InitiateAuth(
	ctx context.Context,
	verifCtx *proto.VerificationContext,
	verifier string,
	sessionID string,
	storeFn auth.StoreVerificationContextFn,
) (*intents.IntentResponseAuthInitiated, error) {
	if verifCtx != nil {
		return nil, fmt.Errorf("unexpected auth session for identity type that does not support it")
	}
	return nil, fmt.Errorf("this identity type does not support initiateAuth")
}

func (p *LegacyAuthProvider) Verify(
	ctx context.Context, verifCtx *proto.VerificationContext, sessionID string, answer string,
) (ident proto.Identity, err error) {
	if verifCtx != nil {
		return proto.Identity{}, fmt.Errorf("unexpected auth session for identity type that does not support it")
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

	ks := &operationKeySet{
		ctx:       ctx,
		iss:       issuer,
		store:     p.store,
		getKeySet: p.GetKeySet,
	}

	if _, err := jws.Verify([]byte(answer), jws.WithKeySet(ks, jws.WithMultipleKeysPerKeyID(false))); err != nil {
		return proto.Identity{}, fmt.Errorf("signature verification: %w", err)
	}

	sessionHash := ethcoder.Keccak256Hash([]byte(strings.ToLower(sessionID))).String()
	validateOptions := []jwt.ValidateOption{
		jwt.WithValidator(withIssuer(idp.Issuer, true)),
		jwt.WithValidator(withSessionHash(sessionHash)),
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

func (p *LegacyAuthProvider) ValidateTenant(ctx context.Context, tenant *proto.TenantData) error {
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

func (p *LegacyAuthProvider) GetKeySet(ctx context.Context, issuer string) (set jwk.Set, err error) {
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
