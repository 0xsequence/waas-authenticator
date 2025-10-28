package tenant

import (
	"context"

	"github.com/0xsequence/waas-authenticator/proto"
)

type contextKeyType string

var (
	accessKeyCtxKey = contextKeyType("access-key")
	originKeyCtxKey = contextKeyType("origin")
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

func WithAccessKey(ctx context.Context, accessKey string) context.Context {
	return context.WithValue(ctx, accessKeyCtxKey, accessKey)
}

func OriginFromContext(ctx context.Context) string {
	v, _ := ctx.Value(originKeyCtxKey).(string)
	return v
}

func WithOrigin(ctx context.Context, origin string) context.Context {
	return context.WithValue(ctx, originKeyCtxKey, origin)
}
