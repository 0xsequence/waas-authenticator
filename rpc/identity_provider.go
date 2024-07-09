package rpc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/0xsequence/go-sequence/intents"
	"github.com/0xsequence/waas-authenticator/data"
	"github.com/0xsequence/waas-authenticator/proto"
	"github.com/0xsequence/waas-authenticator/rpc/crypto"
	"github.com/0xsequence/waas-authenticator/rpc/signing"
	"github.com/0xsequence/waas-authenticator/rpc/tenant"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
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

func (s *RPC) getIDToken(
	ctx context.Context, sess *data.Session, intent *intents.IntentTyped[intents.IntentDataGetIdToken],
) (*intents.IntentResponseIdToken, error) {
	tnt := tenant.FromContext(ctx)

	if len(intent.Data.Nonce) > 128 {
		return nil, fmt.Errorf("invalid nonce")
	}

	sessData, _, err := crypto.DecryptData[*proto.SessionData](ctx, sess.EncryptedKey, sess.Ciphertext, tnt.KMSKeys)
	if err != nil {
		return nil, err
	}

	var identity proto.Identity
	if err := identity.FromString(sessData.Identity); err != nil {
		return nil, fmt.Errorf("parsing session identity: %w", err)
	}

	acc, found, err := s.Accounts.Get(ctx, tnt.ProjectID, identity)
	if err != nil {
		return nil, fmt.Errorf("getting account: %w", err)
	}
	if !found {
		return nil, fmt.Errorf("account not found")
	}

	walletAddr, err := AddressForUser(ctx, tnt, acc.UserID)
	if err != nil {
		return nil, fmt.Errorf("getting wallet address: %w", err)
	}

	aud := fmt.Sprintf("%s/project/%d", s.Config.Builder.BaseURL, tnt.ProjectID)
	iat := time.Now()
	exp := iat.Add(10 * time.Minute)

	b := jwt.NewBuilder().
		Subject(walletAddr).
		Audience([]string{aud}).
		Issuer(s.Config.BaseURL).
		IssuedAt(iat).
		Expiration(exp).
		Claim("auth_time", sessData.CreatedAt.Unix()).
		Claim(s.Config.BaseURL+"/identity", identity)

	if acc.Email != "" {
		b.Claim("email", acc.Email)
	}

	if intent.Data.Nonce != "" {
		b.Claim("nonce", intent.Data.Nonce)
	}

	tok, err := b.Build()
	if err != nil {
		return nil, err
	}

	serialized, err := jwt.NewSerializer().Serialize(tok)
	if err != nil {
		return nil, err
	}

	// these can't fail, thus we ignore the errors
	h := jws.NewHeaders()
	_ = h.Set(jws.AlgorithmKey, jwa.RS256)
	_ = h.Set(jws.KeyIDKey, s.Signer.KeyID())
	_ = h.Set(jws.TypeKey, "JWT")

	mh, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}

	payload := base64.RawURLEncoding.EncodeToString(mh) + "." + base64.RawURLEncoding.EncodeToString(serialized)
	signature, err := s.Signer.Sign(ctx, signing.AlgorithmRsaPkcs1V15Sha256, []byte(payload))
	if err != nil {
		return nil, err
	}

	signed := payload + "." + base64.RawURLEncoding.EncodeToString(signature)
	res := &intents.IntentResponseIdToken{
		IdToken:   signed,
		ExpiresIn: int(exp.Sub(iat).Seconds()),
	}
	return res, nil
}
