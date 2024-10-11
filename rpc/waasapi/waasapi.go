package waasapi

import (
	"context"
	"net/http"

	"github.com/0xsequence/go-sequence/intents"
	proto_wallet "github.com/0xsequence/waas-authenticator/proto/waas"
	"github.com/0xsequence/waas-authenticator/rpc/tenant"
)

func Context(ctx context.Context, optJwtToken ...string) context.Context {
	var jwtToken string
	if len(optJwtToken) == 1 {
		jwtToken = optJwtToken[0]
	} else {
		tntData := tenant.FromContext(ctx)
		jwtToken = tntData.WaasAccessToken
	}

	waasHeader := http.Header{}
	waasHeader.Set("Authorization", "BEARER "+jwtToken)

	accessKey := tenant.AccessKeyFromContext(ctx)
	if accessKey != "" {
		waasHeader.Set("X-Access-Key", accessKey)
	}

	waasCtx, err := proto_wallet.WithHTTPRequestHeaders(ctx, waasHeader)
	if err != nil {
		return ctx
	}
	return waasCtx
}

func ConvertToAPIIntent(intent *intents.Intent) *proto_wallet.Intent {
	signatures := make([]*proto_wallet.Signature, len(intent.Signatures))
	for i, s := range intent.Signatures {
		signatures[i] = &proto_wallet.Signature{
			SessionID: s.SessionID,
			Signature: s.Signature,
		}
	}
	return &proto_wallet.Intent{
		Version:    intent.Version,
		Name:       proto_wallet.IntentName(intent.Name),
		ExpiresAt:  intent.ExpiresAt,
		IssuedAt:   intent.IssuedAt,
		Data:       intent.Data,
		Signatures: signatures,
	}
}
