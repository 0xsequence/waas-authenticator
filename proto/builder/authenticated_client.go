package builder

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

type AuthenticatedClient struct {
	HTTPClient

	m           sync.RWMutex
	cachedToken string
	expiration  time.Time

	sm       *secretsmanager.Client
	secretID string
}

func NewAuthenticatedClient(httpClient HTTPClient, sm *secretsmanager.Client, secretID string) *AuthenticatedClient {
	return &AuthenticatedClient{
		HTTPClient: httpClient,
		sm:         sm,
		secretID:   secretID,
	}
}

func (c *AuthenticatedClient) Do(req *http.Request) (*http.Response, error) {
	ctx := req.Context()

	token, exp := c.getToken()
	if token == "" || time.Now().After(exp) {
		var err error
		token, err = c.fetchToken(ctx)
		if err != nil {
			return nil, err
		}
	}

	h := http.Header{}
	h.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	ctx, err := WithHTTPRequestHeaders(ctx, h)
	if err != nil {
		return nil, err
	}

	return c.Do(req.WithContext(ctx))
}

func (c *AuthenticatedClient) getToken() (string, time.Time) {
	c.m.RLock()
	defer c.m.RUnlock()

	return c.cachedToken, c.expiration
}

func (c *AuthenticatedClient) fetchToken(ctx context.Context) (string, error) {
	out, err := c.sm.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(c.secretID),
	})
	if err != nil {
		return "", err
	}
	if out.SecretString == nil {
		return "", fmt.Errorf("no token found")
	}

	c.m.Lock()
	defer c.m.Unlock()

	c.cachedToken = *out.SecretString
	c.expiration = time.Now().Add(1 * time.Hour)
	return c.cachedToken, nil
}
