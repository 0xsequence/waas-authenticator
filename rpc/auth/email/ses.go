package email

import (
	"context"

	"github.com/0xsequence/waas-authenticator/config"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ses"
	"github.com/aws/aws-sdk-go-v2/service/ses/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type sesSender struct {
	client    *ses.Client
	source    *string
	sourceARN *string
}

func NewSESSender(awsCfg aws.Config, cfg config.SESConfig) Sender {
	if cfg.AccessRoleARN != "" {
		stsClient := sts.NewFromConfig(awsCfg)
		creds := stscreds.NewAssumeRoleProvider(stsClient, cfg.AccessRoleARN)
		awsCfg.Credentials = aws.NewCredentialsCache(creds)
	}

	if cfg.Region != "" {
		awsCfg.Region = cfg.Region
	}

	sender := &sesSender{
		client: ses.NewFromConfig(awsCfg),
	}

	if cfg.Source != "" {
		sender.source = &cfg.Source
	}

	if cfg.SourceARN != "" {
		sender.sourceARN = &cfg.SourceARN
	}

	return sender
}

func (s *sesSender) Send(ctx context.Context, msg *Message) error {
	_, err := s.client.SendEmail(ctx, &ses.SendEmailInput{
		Destination: &types.Destination{
			ToAddresses: []string{msg.Recipient},
		},
		Message: &types.Message{
			Body: &types.Body{
				Html: &types.Content{
					Data:    &msg.HTML,
					Charset: aws.String("UTF-8"),
				},
				Text: &types.Content{
					Data:    &msg.Text,
					Charset: aws.String("UTF-8"),
				},
			},
			Subject: &types.Content{
				Data:    &msg.Subject,
				Charset: aws.String("UTF-8"),
			},
		},
		Source:    s.source,
		SourceArn: s.sourceARN,
	})
	return err
}
