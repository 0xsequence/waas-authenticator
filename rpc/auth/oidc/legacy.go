package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/0xsequence/ethkit/ethcoder"
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

// InitiateAuth returns an error in the legacy flow.
func (v *LegacyAuthProvider) InitiateAuth(
	ctx context.Context,
	verifCtx *proto.VerificationContext,
	verifier string,
	intent *intents.Intent,
	storeFn auth.StoreVerificationContextFn,
) (*intents.IntentResponseAuthInitiated, error) {
	if verifCtx != nil {
		return nil, fmt.Errorf("unexpected auth session for identity type that does not support it")
	}
	return nil, fmt.Errorf("this identity type does not support initiateAuth")
}

func (v *LegacyAuthProvider) Verify(
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
		store:     v.store,
		getKeySet: v.GetKeySet,
	}

	if _, err := jws.Verify([]byte(answer), jws.WithKeySet(ks, jws.WithMultipleKeysPerKeyID(false))); err != nil {
		return proto.Identity{}, fmt.Errorf("signature verification: %w", err)
	}

	sessionHash := ethcoder.Keccak256Hash([]byte(strings.ToLower(sessionID))).String()
	validateOptions := []jwt.ValidateOption{
		jwt.WithValidator(withIssuer(idp.Issuer)),
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

func (v *LegacyAuthProvider) ValidateTenant(ctx context.Context, tenant *proto.TenantData) error {
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
			if _, err := v.GetKeySet(ctx, provider.Issuer); err != nil {
				return err
			}
			return nil
		})
	}

	return wg.Wait()
}

func (v *LegacyAuthProvider) GetKeySet(ctx context.Context, issuer string) (set jwk.Set, err error) {
	jwksURL, err := fetchJWKSURL(ctx, v.client, issuer)
	if err != nil {
		return nil, fmt.Errorf("fetch issuer keys: %w", err)
	}

	keySet, err := jwk.Fetch(ctx, jwksURL, jwk.WithHTTPClient(tracing.WrapClientWithContext(ctx, v.client)))
	if err != nil {
		return nil, fmt.Errorf("fetch issuer keys: %w", err)
	}
	return keySet, nil
}

func withIssuer(expectedIss string) jwt.ValidatorFunc {
	return func(ctx context.Context, tok jwt.Token) jwt.ValidationError {
		if normalizeIssuer(tok.Issuer()) != expectedIss {
			return jwt.NewValidationError(fmt.Errorf("iss not satisfied"))
		}
		return nil
	}
}

func withSessionHash(expectedSessionHash string) jwt.ValidatorFunc {
	return func(ctx context.Context, tok jwt.Token) jwt.ValidationError {
		sessHashClaim, ok := tok.Get("sequence:session_hash")
		if ok && sessHashClaim == expectedSessionHash {
			return nil
		}

		nonceClaim, ok := tok.Get("nonce")
		if !ok {
			return jwt.NewValidationError(fmt.Errorf("nonce not satisfied"))
		}

		nonceVal, _ := nonceClaim.(string)
		if nonceVal != "" && nonceVal == expectedSessionHash {
			return nil
		}

		return jwt.NewValidationError(fmt.Errorf("nonce not satisfied: %s != %s", nonceVal, expectedSessionHash))
	}
}

func withAudience(expectedAudience []string) jwt.ValidatorFunc {
	return func(ctx context.Context, tok jwt.Token) jwt.ValidationError {
		tokAudiences := tok.Audience()
		for _, aud := range expectedAudience {
			if slices.Contains(tokAudiences, aud) {
				return nil
			}
		}

		return jwt.NewValidationError(fmt.Errorf("aud not satisfied"))
	}
}

func getOIDCProvider(ctx context.Context, issuer string) *proto.OpenIdProvider {
	tntData := tenant.FromContext(ctx)
	for _, idp := range tntData.OIDCProviders {
		if idp.Issuer == issuer {
			return idp
		}
	}
	return nil
}

func fetchJWKSURL(ctx context.Context, client HTTPClient, iss string) (string, error) {
	// Construct the URL to the issuer's .well-known/openid-configuration endpoint
	issuerConfigURL := normalizeIssuer(iss) + "/.well-known/openid-configuration"

	req, err := http.NewRequest(http.MethodGet, issuerConfigURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", errors.New("failed to fetch openid configuration")
	}

	var config map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return "", err
	}

	jwksURI, ok := config["jwks_uri"].(string)
	if !ok {
		return "", errors.New("jwks_uri not found in openid configuration")
	}

	return jwksURI, nil
}

func normalizeIssuer(iss string) string {
	if !strings.HasPrefix(iss, "https://") && !strings.HasPrefix(iss, "http://") {
		return "https://" + iss
	}
	return iss
}

func getEmailFromToken(tok jwt.Token) string {
	emailClaim, ok := tok.Get("email")
	if !ok {
		return ""
	}
	email, _ := emailClaim.(string)
	return email
}
