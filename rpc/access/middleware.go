package access

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"time"

	"github.com/0xsequence/waas-authenticator/config"
	"github.com/0xsequence/waas-authenticator/proto"
	"github.com/0xsequence/waas-authenticator/rpc/tenant"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func JWTAuthMiddleware(cfg config.AdminConfig) func(http.Handler) http.Handler {
	badConfig := func(err error) func(next http.Handler) http.Handler {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				werr := fmt.Errorf("service config jwt public key is invalid: %w", err)
				proto.RespondWithError(w, proto.ErrUnauthorized.WithCause(werr))
			})
		}
	}

	publicKeyBlock, _ := pem.Decode([]byte(cfg.PublicKey))
	if publicKeyBlock == nil {
		return badConfig(fmt.Errorf("pem decode failed"))
	}
	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		return badConfig(err)
	}

	ja := jwtauth.New(jwa.RS256.String(), nil, publicKey, jwt.WithAcceptableSkew(1*time.Minute))

	return chi.Chain(
		accessKeyMiddleware,
		jwtauth.Verifier(ja),
		jwtAuthenticator(ja),
	).Handler
}

func accessKeyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		accessKey := r.Header.Get("x-access-key")
		if accessKey != "" {
			ctx = tenant.WithAccessKey(ctx, accessKey)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func jwtAuthenticator(ja *jwtauth.JWTAuth) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		hfn := func(w http.ResponseWriter, r *http.Request) {
			token, _, err := jwtauth.FromContext(r.Context())

			if err != nil {
				proto.RespondWithError(w, proto.ErrUnauthorized.WithCause(err))
				return
			}

			if token == nil || jwt.Validate(token, ja.ValidateOptions()...) != nil {
				proto.RespondWithError(w, proto.ErrUnauthorized.WithCause(err))
				return
			}

			// Token is authenticated, pass it through
			next.ServeHTTP(w, r)
		}
		return http.HandlerFunc(hfn)
	}
}
