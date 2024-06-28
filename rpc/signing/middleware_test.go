package signing

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMiddleware(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	signer := &mockSigner{}
	server := httptest.NewServer(Middleware(signer)(handler))
	defer server.Close()

	testCases := map[string]struct {
		acceptSignature string
		assertFn        func(t *testing.T, res *http.Response, err error)
	}{
		"NoAcceptSignature": {
			acceptSignature: "",
			assertFn: func(t *testing.T, res *http.Response, err error) {
				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, res.StatusCode)
				assert.Empty(t, res.Header.Get("signature"))
				assert.Empty(t, res.Header.Get("signature-input"))
			},
		},
		"BasicAcceptSignature": {
			acceptSignature: "sig=()",
			assertFn: func(t *testing.T, res *http.Response, err error) {
				sigInputRegex := regexp.MustCompile(`^sig=\("content-digest"\);created=[0-9]+;keyid="KEYID";alg="rsa-v1_5-sha256"$`)

				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, res.StatusCode)

				sigInput := res.Header.Get("signature-input")
				assert.NotEmpty(t, sigInput)
				assert.Regexp(t, sigInputRegex, sigInput)

				body, _ := io.ReadAll(res.Body)
				digest := sha256.Sum256(body)
				message := strings.Join([]string{
					fmt.Sprintf(`"content-digest": sha-256=:%s:`, base64.StdEncoding.EncodeToString(digest[:])),
					fmt.Sprintf(`"@signature-params": %s`, strings.TrimPrefix(sigInput, "sig=")),
				}, "\n")

				signature, _ := signer.Sign(context.Background(), AlgorithmRsaPkcs1V15Sha256, []byte(message))
				expect := fmt.Sprintf("sig=:%s:", base64.StdEncoding.EncodeToString(signature))

				assert.Equal(t, expect, res.Header.Get("signature"))
			},
		},
		"FullAcceptSignature": {
			acceptSignature: `sig=("content-digest");created;keyid="KEYID";alg="rsa-v1_5-sha256";nonce="NONCE"`,
			assertFn: func(t *testing.T, res *http.Response, err error) {
				sigInputRegex := regexp.MustCompile(`^sig=\("content-digest"\);created=[0-9]+;keyid="KEYID";alg="rsa-v1_5-sha256";nonce="NONCE"$`)

				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, res.StatusCode)

				sigInput := res.Header.Get("signature-input")
				assert.NotEmpty(t, sigInput)
				assert.Regexp(t, sigInputRegex, sigInput)

				body, _ := io.ReadAll(res.Body)
				digest := sha256.Sum256(body)
				message := strings.Join([]string{
					fmt.Sprintf(`"content-digest": sha-256=:%s:`, base64.StdEncoding.EncodeToString(digest[:])),
					fmt.Sprintf(`"@signature-params": %s`, strings.TrimPrefix(sigInput, "sig=")),
				}, "\n")

				signature, _ := signer.Sign(context.Background(), AlgorithmRsaPkcs1V15Sha256, []byte(message))
				expect := fmt.Sprintf("sig=:%s:", base64.StdEncoding.EncodeToString(signature))

				assert.Equal(t, expect, res.Header.Get("signature"))
			},
		},
		"ExtendedAcceptSignature": {
			acceptSignature: `sig=("@method" "@status" "@target-uri" "content-digest");alg="rsa-pss-sha512"`,
			assertFn: func(t *testing.T, res *http.Response, err error) {
				sigInputRegex := regexp.MustCompile(`^sig=\("@method" "@status" "@target-uri" "content-digest"\);created=[0-9]+;keyid="KEYID";alg="rsa-pss-sha512"$`)

				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, res.StatusCode)

				sigInput := res.Header.Get("signature-input")
				assert.NotEmpty(t, sigInput)
				assert.Regexp(t, sigInputRegex, sigInput)

				body, _ := io.ReadAll(res.Body)
				digest := sha256.Sum256(body)
				message := strings.Join([]string{
					`"@method": GET`,
					`"@status": 200`,
					fmt.Sprintf(`"@target-uri": %s`, strings.Replace(server.URL, "http://", "https://", 1)),
					fmt.Sprintf(`"content-digest": sha-256=:%s:`, base64.StdEncoding.EncodeToString(digest[:])),
					fmt.Sprintf(`"@signature-params": %s`, strings.TrimPrefix(sigInput, "sig=")),
				}, "\n")

				signature, _ := signer.Sign(context.Background(), AlgorithmRsaPssSha512, []byte(message))
				expect := fmt.Sprintf("sig=:%s:", base64.StdEncoding.EncodeToString(signature))

				assert.Equal(t, expect, res.Header.Get("signature"))
			},
		},
	}

	for label, tc := range testCases {
		t.Run(label, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, server.URL, nil)
			require.NoError(t, err)

			if tc.acceptSignature != "" {
				req.Header.Set("accept-signature", tc.acceptSignature)
			}

			res, err := http.DefaultClient.Do(req)
			tc.assertFn(t, res, err)
		})
	}
}

type mockSigner struct{}

func (m mockSigner) Sign(ctx context.Context, alg Algorithm, message []byte) ([]byte, error) {
	sum := sha256.Sum256(message)
	res := append([]byte(alg+":"), sum[:]...)

	return res, nil
}

func (m mockSigner) KeyID() string {
	return "KEYID"
}

func (m mockSigner) PublicKey(ctx context.Context) (jwk.RSAPublicKey, error) {
	panic("implement me")
}
