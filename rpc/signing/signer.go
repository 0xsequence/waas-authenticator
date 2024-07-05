package signing

import (
	"context"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

type Signer interface {
	Sign(ctx context.Context, alg Algorithm, message []byte) ([]byte, error)
	KeyID() string
	PublicKey(ctx context.Context) (jwk.RSAPublicKey, error)
}
