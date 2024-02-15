package rpc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/0xsequence/waas-authenticator/proto"
	"github.com/0xsequence/waas-authenticator/rpc/tenant"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

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
		sessAddrClaim, ok := tok.Get("sequence:session_hash")
		if ok && sessAddrClaim == expectedSessionHash {
			return nil
		}

		nonceClaim, ok := tok.Get("nonce")
		if !ok {
			// TODO: we might always want to require nonce to be present
			return nil
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

func verifyIdentity(ctx context.Context, client HTTPClient, idToken string, sessionHash string) (proto.Identity, error) {
	tok, err := jwt.Parse([]byte(idToken), jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return proto.Identity{}, fmt.Errorf("parse JWT: %w", err)
	}

	idp := getOIDCProvider(ctx, normalizeIssuer(tok.Issuer()))
	if idp == nil {
		return proto.Identity{}, fmt.Errorf("issuer %q not valid for this tenant", tok.Issuer())
	}

	keySet, err := getProviderKeySet(ctx, client, normalizeIssuer(idp.Issuer))
	if err != nil {
		return proto.Identity{}, err
	}

	if _, err := jws.Verify([]byte(idToken), jws.WithKeySet(keySet)); err != nil {
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
		Issuer:  tok.Issuer(),
		Subject: tok.Subject(),
		Email:   getEmailFromToken(tok),
	}
	return identity, nil
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

func getProviderKeySet(ctx context.Context, client HTTPClient, issuer string) (jwk.Set, error) {
	jwksURL, err := fetchJWKSURL(ctx, client, issuer)
	if err != nil {
		return nil, fmt.Errorf("fetch issuer keys: %w", err)
	}

	keySet, err := jwk.Fetch(ctx, jwksURL, jwk.WithHTTPClient(client))
	if err != nil {
		return nil, fmt.Errorf("fetch issuer keys: %w", err)
	}
	return keySet, nil
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
	// TODO: we might want to relax this a bit and not depend so much on the `email_verified` claim
	emailVerifiedClaim, ok := tok.Get("email_verified")
	if !ok {
		return ""
	}

	verified := false
	switch v := emailVerifiedClaim.(type) {
	case bool:
		verified = v
	case string:
		verified = strings.TrimSpace(strings.ToLower(v)) == "true"
	}
	if !verified {
		return ""
	}

	emailClaim, ok := tok.Get("email")
	if !ok {
		return ""
	}
	email, _ := emailClaim.(string)
	return email
}
