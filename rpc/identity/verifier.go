package identity

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/0xsequence/waas-authenticator/proto"
	"github.com/goware/cachestore"
	"github.com/goware/cachestore/cachestorectl"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
	Get(string) (*http.Response, error)
}

type Verifier struct {
	client HTTPClient
	store  cachestore.Store[jwk.Key]
}

func NewVerifier(cacheBackend cachestore.Backend, client HTTPClient) (*Verifier, error) {
	if client == nil {
		client = http.DefaultClient
	}
	store, err := cachestorectl.Open[jwk.Key](cacheBackend)
	if err != nil {
		return nil, err
	}
	return &Verifier{
		client: client,
		store:  store,
	}, nil
}

func (v *Verifier) Verify(ctx context.Context, idToken string, sessionHash string) (proto.Identity, error) {
	tok, err := jwt.Parse([]byte(idToken), jwt.WithVerify(false), jwt.WithValidate(false))
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

	if _, err := jws.Verify([]byte(idToken), jws.WithKeySet(ks, jws.WithMultipleKeysPerKeyID(false))); err != nil {
		return proto.Identity{}, fmt.Errorf("signature verification: %w", err)
	}

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
