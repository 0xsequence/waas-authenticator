package email

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/0xsequence/waas-authenticator/rpc/signing"
)

// signedChallenge is the server-side salt. Only the client salt is sent to the device.
func signedChallenge(ctx context.Context, signer signing.Signer, projectID uint64, sessionID, verifier, answer string, expires time.Time) (string, error) {
	digest := sha256.Sum256([]byte(answer))
	claims := struct {
		Issuer       string `json:"iss"`
		Audience     string `json:"aud"`
		ExpiresAt    int64  `json:"exp"`
		ProjectID    uint64 `json:"project_id"`
		SessionID    string `json:"session_id"`
		Verifier     string `json:"verifier"`
		AnswerDigest string `json:"answer_digest"`
	}{"waas-authenticator", "waas-guard-email", expires.Unix(), projectID, strings.ToLower(sessionID), verifier, base64.RawURLEncoding.EncodeToString(digest[:])}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	encode := base64.RawURLEncoding.EncodeToString
	input := encode([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + encode(payload)
	signature, err := signer.Sign(ctx, signing.AlgorithmRsaPkcs1V15Sha256, []byte(input))
	if err != nil {
		return "", err
	}
	return input + "." + encode(signature), nil
}
