package tenant

import (
	"context"

	"github.com/0xsequence/waas-authenticator/proto"
)

type contextKeyType string

var contextKey = contextKeyType("tenant-data")

func FromContext(ctx context.Context) *proto.TenantData {
	v, _ := ctx.Value(contextKey).(*proto.TenantData)
	return v
}
