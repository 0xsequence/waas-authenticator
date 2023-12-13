package tenant

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/0xsequence/waas-authenticator/data"
	"github.com/0xsequence/waas-authenticator/proto"
	"github.com/0xsequence/waas-authenticator/rpc/crypto"
)

// Middleware validates that the tenant sent in X-Sequence-Tenant header is valid and stores it in context.
func Middleware(tenants *data.TenantTable, tenantKeys []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			tenantID, _ := strconv.Atoi(r.Header.Get("x-sequence-tenant"))
			tenant, found, err := tenants.GetLatest(ctx, uint64(tenantID))
			if err != nil || !found {
				proto.RespondWithError(w, fmt.Errorf("invalid tenant: %q", tenantID))
				return
			}

			tntData, _, err := crypto.DecryptData[*proto.TenantData](ctx, tenant.EncryptedKey, tenant.Ciphertext, tenantKeys)
			if err != nil {
				proto.RespondWithError(w, fmt.Errorf("could not decrypt tenant data: %q", tenantID))
				return
			}

			ctx = context.WithValue(ctx, contextKey, tntData)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
