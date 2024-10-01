package awscreds

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// Provider implements aws.CredentialsProvider.
type Provider struct {
	baseURL string
	client  HTTPClient
}

// NewProvider returns a new Provider using the given HTTPClient.
func NewProvider(client HTTPClient, baseURL string) *Provider {
	return &Provider{
		baseURL: baseURL,
		client:  client,
	}
}

// Retrieve returns a new set of aws.Credentials.
func (p *Provider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	cred, err := p.getAWSCredential(ctx)
	if err != nil {
		return aws.Credentials{}, err
	}
	return *cred, nil
}

func (p *Provider) getAWSCredential(ctx context.Context) (*aws.Credentials, error) {
	profileName, err := p.getInstanceProfileName(ctx)
	if err != nil {
		return nil, err
	}

	u, err := url.JoinPath(p.baseURL, "latest/meta-data/iam/security-credentials", profileName)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	res, err := p.client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("doing HTTP request: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %s", res.Status)
	}

	var cred struct {
		AccessKeyID     string `json:"AccessKeyId"`
		SecretAccessKey string `json:"SecretAccessKey"`
		Token           string `json:"Token"`
	}
	if err := json.NewDecoder(res.Body).Decode(&cred); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return &aws.Credentials{
		AccessKeyID:     cred.AccessKeyID,
		SecretAccessKey: cred.SecretAccessKey,
		SessionToken:    cred.Token,
		Expires:         time.Now().Add(time.Hour),
		CanExpire:       true,
	}, nil
}

func (p *Provider) getInstanceProfileName(ctx context.Context) (string, error) {
	u, err := url.JoinPath(p.baseURL, "latest/meta-data/iam/security-credentials/")
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}

	res, err := p.client.Do(req.WithContext(ctx))
	if err != nil {
		return "", fmt.Errorf("doing HTTP request: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status: %s", res.Status)
	}

	b, err := io.ReadAll(res.Body)
	if err != nil {
		return "", fmt.Errorf("reading response body: %w", err)
	}
	return string(b), nil
}
