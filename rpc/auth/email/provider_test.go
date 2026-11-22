package email

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/0xsequence/waas-authenticator/rpc/signing"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/require"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestExtractVerifier(t *testing.T) {
	testCases := []struct {
		input             string
		expectedEmail     string
		expectedSessionID string
		expectError       bool
	}{
		{
			input:       "user@example.com",
			expectError: true,
		},
		{
			input:             "user@example.com;0x1234",
			expectedEmail:     "user@example.com",
			expectedSessionID: "0x1234",
		},
		{
			input:             "  USER@example.COM  ;0x1234",
			expectedEmail:     "user@example.com",
			expectedSessionID: "0x1234",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			email, sessionID, err := extractVerifier(tc.input)
			assert.Equal(t, tc.expectedEmail, email)
			assert.Equal(t, tc.expectedSessionID, sessionID)
			if tc.expectError {
				assert.Error(t, err)
			}
		})
	}
}

type challengeSigner struct {
	signing.Signer
	key *rsa.PrivateKey
}

func (s challengeSigner) Sign(_ context.Context, alg signing.Algorithm, input []byte) ([]byte, error) {
	if alg != signing.AlgorithmRsaPkcs1V15Sha256 {
		return nil, fmt.Errorf("unexpected signing algorithm")
	}
	hashed := sha256.Sum256(input)
	return rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, hashed[:])
}

func TestSignedChallenge(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	expiry := time.Now().Add(30 * time.Minute)
	token, err := signedChallenge(context.Background(), challengeSigner{key: key}, 42, "SESSION", "test@example.org;SESSION", "client-answer", expiry)
	require.NoError(t, err)
	parsed, err := jwt.Parse([]byte(token), jwt.WithKey(jwa.RS256, &key.PublicKey), jwt.WithValidate(true), jwt.WithIssuer("waas-authenticator"), jwt.WithAudience("waas-guard-email"))
	require.NoError(t, err)
	require.Equal(t, expiry.Unix(), parsed.Expiration().Unix())
	for field, want := range map[string]any{"project_id": float64(42), "session_id": "session", "verifier": "test@example.org;SESSION"} {
		got, ok := parsed.Get(field)
		require.True(t, ok)
		require.Equal(t, want, got)
	}
	hashed := sha256.Sum256([]byte("client-answer"))
	got, ok := parsed.Get("answer_digest")
	require.True(t, ok)
	require.Equal(t, base64.RawURLEncoding.EncodeToString(hashed[:]), got)
}
