package tenant

import (
	"context"

	"github.com/0xsequence/waas-authenticator/proto"
)

type contextKeyType string

var (
	accessKeyCtxKey = contextKeyType("access-key")
	tenantCtxKey    = contextKeyType("tenant-data")
)

func FromContext(ctx context.Context) *proto.TenantData {
	v, _ := ctx.Value(tenantCtxKey).(*proto.TenantData)
	return v
}

func AccessKeyFromContext(ctx context.Context) string {
	v, _ := ctx.Value(accessKeyCtxKey).(string)
	return v
}
