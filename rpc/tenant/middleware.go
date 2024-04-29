package tenant

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/0xsequence/waas-authenticator/data"
	"github.com/0xsequence/waas-authenticator/proto"
	"github.com/0xsequence/waas-authenticator/rpc/crypto"
	"github.com/0xsequence/waas-authenticator/rpc/tracing"
)

// Middleware validates that the tenant sent in X-Access-Key header is valid and stores it in context.
func Middleware(tenants *data.TenantTable, tenantKeys []string) func(http.Handler) http.Handler {
	runMiddleware := func(w http.ResponseWriter, r *http.Request) (ctx context.Context, err error) {
		traceCtx, span := tracing.Span(r.Context(), "tenant.Middleware")
		defer func() {
			if err != nil {
				span.RecordError(err)
			}
			span.End()
		}()

		ctx = r.Context()

		// Place the access key in context as it's used by services downstream
		accessKey := r.Header.Get("x-access-key")
		if accessKey != "" {
			ctx = WithAccessKey(ctx, accessKey)
		}

		// Get projectID from the header populated by the ingress service
		projectHeader := r.Header.Get("x-sequence-project")
		if projectHeader == "" {
			return nil, fmt.Errorf("missing X-Sequence-Project header")
		}

		projectID, err := strconv.Atoi(strings.TrimSpace(projectHeader))
		if err != nil {
			return nil, fmt.Errorf("parse project ID: %w", err)
		}

		// Find tenant based on project id
		tenant, found, err := tenants.GetLatest(traceCtx, uint64(projectID))
		if err != nil {
			return nil, fmt.Errorf("could not retrieve tenant: %w", err)
		}
		if !found {
			return nil, fmt.Errorf("invalid tenant: %v", projectID)
		}

		tntData, _, err := crypto.DecryptData[*proto.TenantData](traceCtx, tenant.EncryptedKey, tenant.Ciphertext, tenantKeys)
		if err != nil {
			return nil, fmt.Errorf("could not decrypt tenant data: %v", projectID)
		}

		origin := r.Header.Get("origin")
		if origin != "" {
			if !tntData.AllowedOrigins.MatchAny(origin) {
				return nil, fmt.Errorf("origin not allowed: %s", origin)
			}
		}

		return context.WithValue(ctx, tenantCtxKey, tntData), nil
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, err := runMiddleware(w, r)
			if err != nil {
				proto.RespondWithError(w, err)
				return
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
