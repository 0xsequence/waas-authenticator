package tenant

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/0xsequence/waas-authenticator/data"
	"github.com/0xsequence/waas-authenticator/proto"
	"github.com/0xsequence/waas-authenticator/rpc/crypto"
)

// Middleware validates that the tenant sent in X-Access-Key header is valid and stores it in context.
func Middleware(tenants *data.TenantTable, tenantKeys []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Get projectID from the header populated by the ingress service
			projectHeader := r.Header.Get("x-sequence-project")
			if projectHeader == "" {
				proto.RespondWithError(w, fmt.Errorf("missing X-Sequence-Project header"))
				return
			}

			projectID, err := strconv.Atoi(strings.TrimSpace(projectHeader))
			if err != nil {
				proto.RespondWithError(w, fmt.Errorf("parse project ID: %w", err))
				return
			}

			// Find tenant based on project id
			tenant, found, err := tenants.GetLatest(ctx, uint64(projectID))
			if err != nil {
				proto.RespondWithError(w, fmt.Errorf("could not retrieve tenant: %w", err))
				return
			}
			if !found {
				proto.RespondWithError(w, fmt.Errorf("invalid tenant: %v", projectID))
				return
			}

			tntData, _, err := crypto.DecryptData[*proto.TenantData](ctx, tenant.EncryptedKey, tenant.Ciphertext, tenantKeys)
			if err != nil {
				proto.RespondWithError(w, fmt.Errorf("could not decrypt tenant data: %v", projectID))
				return
			}

			origin := r.Header.Get("origin")
			if origin != "" && len(tntData.AllowedOrigins) > 0 {
				if !slices.Contains(tntData.AllowedOrigins, origin) {
					proto.RespondWithError(w, fmt.Errorf("origin not allowed"))
					return
				}
			}

			ctx = context.WithValue(ctx, tenantCtxKey, tntData)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
