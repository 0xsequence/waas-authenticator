package rpc

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
)

type openidConfig struct {
	JWKSURI string `json:"jwks_uri"`
}

type publicKey struct {
	Alg string `json:"alg"`
	E   string `json:"e"`
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n"`
	Use string `json:"use"`
}

type jwks struct {
	Keys []publicKey `json:"keys"`
}

func (s *RPC) handleOpenidConfiguration(w http.ResponseWriter, r *http.Request) {
	cfg := &openidConfig{
		JWKSURI: s.Config.BaseURL + "/.well-known/jwks.json",
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(cfg)
}

func (s *RPC) handleJWKS(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pubKey, err := s.Signer.PublicKey(ctx)
	if err != nil {
		panic(err)
	}

	pkd := jwks{Keys: []publicKey{
		{
			Alg: "RS256",
			E:   base64.RawURLEncoding.EncodeToString(pubKey.E()),
			Kid: pubKey.KeyID(),
			Kty: pubKey.KeyType().String(),
			N:   base64.RawURLEncoding.EncodeToString(pubKey.N()),
			Use: "sig",
		},
	}}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(pkd)
}
