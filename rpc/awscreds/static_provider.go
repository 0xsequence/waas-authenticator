package awscreds

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
)

type StaticProvider aws.Credentials

func (p *StaticProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	if p == nil {
		return aws.Credentials{}, nil
	}
	return aws.Credentials(*p), nil
}
