package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/0xsequence/waas-authenticator/proto"
	"github.com/0xsequence/waas-authenticator/rpc/tenant"
	"github.com/0xsequence/waas-authenticator/rpc/tracing"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func (v *Verifier) GetKeySet(ctx context.Context, issuer string) (set jwk.Set, err error) {
	ctx, span := tracing.Span(ctx, "identity.GetKeySet")
	defer func() {
		if err != nil {
			span.RecordError(err)
		}
		span.End()
	}()

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
