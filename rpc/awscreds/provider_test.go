package awscreds_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/0xsequence/waas-authenticator/rpc/awscreds"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProvider_Retrieve(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest/meta-data/iam/security-credentials/":
			w.WriteHeader(200)
			w.Write([]byte("PROFILE"))
		case "/latest/meta-data/iam/security-credentials/PROFILE":
			w.WriteHeader(200)
			w.Write([]byte(`{"AccessKeyId":"AccessKeyID","SecretAccessKey":"SecretAccessKey","Token":"SessionToken"}`))
		default:
			w.WriteHeader(400)
			w.Write([]byte("Wrong path"))
		}
	}))

	provider := awscreds.NewProvider(http.DefaultClient, server.URL)
	creds, err := provider.Retrieve(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "AccessKeyID", creds.AccessKeyID)
	assert.Equal(t, "SecretAccessKey", creds.SecretAccessKey)
	assert.Equal(t, "SessionToken", creds.SessionToken)
}
