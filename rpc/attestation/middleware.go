package attestation

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/0xsequence/nitrocontrol/enclave"
	"github.com/0xsequence/waas-authenticator/proto"
	"github.com/0xsequence/waas-authenticator/rpc/tracing"
)

// Middleware is an HTTP middleware that issues an attestation document request to the enclave's NSM.
// The result wrapped in the Attestation type is then set in the context available to subsequent handlers.
// It also sets the X-Attestation-Document HTTP header to the Base64-encoded representation of the document.
//
// If the HTTP request includes an X-Attestation-Nonce header, its value is sent to the NSM and included in
// the final attestation document.
func Middleware(enc *enclave.Enclave) func(http.Handler) http.Handler {
	runMiddleware := func(w http.ResponseWriter, r *http.Request) (ctx context.Context, cancelFunc func() error, err error) {
		ctx, span := tracing.Span(r.Context(), "attestation.Middleware")
		defer func() {
			if err != nil {
				span.RecordError(err)
			}
			span.End()
		}()

		var nonce []byte
		if nonceVal := r.Header.Get("X-Attestation-Nonce"); nonceVal != "" {
			nonceVal = strings.TrimSpace(nonceVal)
			if len(nonceVal) > 32 {
				return nil, nil, fmt.Errorf("X-Attestation-Nonce value cannot be longer than 32")
			}
			nonce = []byte(nonceVal)
		}

		att, err := enc.GetAttestation(ctx, nonce)
		if err != nil {
			return nil, nil, err
		}

		w.Header().Set("X-Attestation-Document", base64.StdEncoding.EncodeToString(att.Document()))
		return context.WithValue(r.Context(), contextKey, att), att.Close, nil
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel, err := runMiddleware(w, r)
			if err != nil {
				proto.RespondWithError(w, err)
				return
			}
			defer cancel()
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
