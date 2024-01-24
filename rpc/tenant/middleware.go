package tenant

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/http"
	"slices"

	"github.com/0xsequence/waas-authenticator/data"
	"github.com/0xsequence/waas-authenticator/proto"
	"github.com/0xsequence/waas-authenticator/rpc/crypto"
	"github.com/jxskiss/base62"
)

// Middleware validates that the tenant sent in X-Access-Key header is valid and stores it in context.
func Middleware(tenants *data.TenantTable, tenantKeys []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Get projectID based on access key header which is encoded in the value
			// and place the access key on the context.
			accessKey := r.Header.Get("x-access-key")
			if accessKey != "" {
				ctx = WithAccessKey(ctx, accessKey)
			}

			projectID, err := decodeProjectIDFromAccessKey(accessKey)
			if err != nil {
				proto.RespondWithError(w, fmt.Errorf("invalid tenant: %v", projectID))
				return
			}

			// Find tenant based on project id
			tenant, found, err := tenants.GetLatest(ctx, projectID)
			if err != nil || !found {
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

func decodeProjectIDFromAccessKey(accessKey string) (uint64, error) {
	buf, err := base62.DecodeString(accessKey)
	if err != nil || len(buf) < 8 {
		return 0, fmt.Errorf("invalid access key")
	}
	return binary.BigEndian.Uint64(buf[:8]), nil
}
