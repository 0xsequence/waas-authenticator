package enclave

import (
	"context"

	"github.com/0xsequence/nsm"
)

func NitroProvider(_ context.Context) (Session, error) {
	return nsm.OpenDefaultSession()
}
