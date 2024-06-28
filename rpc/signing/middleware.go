package signing

import (
	"bytes"
	"net/http"

	"github.com/0xsequence/waas-authenticator/proto"
	"github.com/go-chi/chi/v5/middleware"
)

func Middleware(signer Signer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Accept-Signature") == "" {
				next.ServeHTTP(w, r)
				return
			}

			var body bytes.Buffer
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			ww.Tee(&body)
			ww.Discard()

			next.ServeHTTP(ww, r)

			b, err := newHTTPSignatureBuilder(signer, body.Bytes(), r, ww.Header(), ww.Status())
			if err != nil {
				proto.RespondWithError(w, err)
				return
			}

			if err := b.Generate(r.Context()); err != nil {
				proto.RespondWithError(w, err)
				return
			}

			w.WriteHeader(ww.Status())
			if _, err := body.WriteTo(w); err != nil {
				proto.RespondWithError(w, err)
			}
		})
	}
}
