package access

import (
	"fmt"
	"net/http"

	"github.com/0xsequence/waas-authenticator/config"
	"github.com/0xsequence/waas-authenticator/proto"
	"github.com/gliderlabs/ssh"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// TODO: review / modify ..
func Middleware(cfg config.AdminConfig) func(http.Handler) http.Handler {
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(cfg.PublicKey))
	if err != nil {
		panic(fmt.Errorf("parse admin public key: %w", err))
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := jwt.ParseHeader(r.Header, "Authorization", jwt.WithKey(jwa.RS256, key))
			if err != nil {
				proto.RespondWithError(w, proto.ErrUnauthorized.WithCause(err))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
