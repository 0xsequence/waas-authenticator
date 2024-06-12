package signing

import (
	"bytes"
	"io"
	"net/http"

	"github.com/0xsequence/waas-authenticator/proto"
)

func Middleware(signer Signer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Accept-Signature") == "" {
				next.ServeHTTP(w, r)
				return
			}

			var body bytes.Buffer
			ww := newWrappedRW(w, &body)

			next.ServeHTTP(ww, r)

			b, err := newHTTPSignatureBuilder(signer, &body, r, ww.Header(), ww.status)
			if err != nil {
				proto.RespondWithError(w, err)
				return
			}

			if err := b.Generate(r.Context()); err != nil {
				proto.RespondWithError(w, err)
				return
			}

			if err := ww.finalize(); err != nil {
				proto.RespondWithError(w, err)
			}
		})
	}
}

type wrappedRW struct {
	http.ResponseWriter
	body        *bytes.Buffer
	wroteHeader bool
	status      int
	tee         io.Writer
}

func newWrappedRW(w http.ResponseWriter, tee io.Writer) *wrappedRW {
	return &wrappedRW{
		ResponseWriter: w,
		body:           &bytes.Buffer{},
		tee:            tee,
	}
}

func (w *wrappedRW) Write(p []byte) (n int, err error) {
	if !w.wroteHeader {
		w.status = http.StatusOK
		w.wroteHeader = true
	}
	if w.tee != nil {
		if n, err := w.tee.Write(p); err != nil {
			return n, err
		}
	}
	return w.body.Write(p)
}

func (w *wrappedRW) WriteHeader(code int) {
	if !w.wroteHeader {
		w.status = code
		w.wroteHeader = true
	}
}

func (w *wrappedRW) finalize() error {
	w.ResponseWriter.WriteHeader(w.status)
	_, err := io.Copy(w.ResponseWriter, w.body)
	return err
}
