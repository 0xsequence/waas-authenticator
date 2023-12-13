package attestation

import (
	"context"

	"github.com/0xsequence/nitrocontrol/enclave"
)

type contextKeyType string

var contextKey = contextKeyType("attestation")

func FromContext(ctx context.Context) *enclave.Attestation {
	v, _ := ctx.Value(contextKey).(*enclave.Attestation)
	return v
}
