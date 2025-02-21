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
	cfg    config.SESConfig
	awsCfg aws.Config
}

func NewSESSender(awsCfg aws.Config, cfg config.SESConfig) Sender {
	sender := &sesSender{
		cfg:    cfg,
		awsCfg: awsCfg,
	}

	return sender
}

func (s *sesSender) Send(ctx context.Context, msg *Message) error {
	awsCfg := s.awsCfg
	accessRoleARN := s.cfg.AccessRoleARN
	if msg.AccessRoleARN != "" {
		accessRoleARN = msg.AccessRoleARN
	}
	if accessRoleARN != "" {
		stsClient := sts.NewFromConfig(awsCfg)
		creds := stscreds.NewAssumeRoleProvider(stsClient, accessRoleARN)
		awsCfg.Credentials = aws.NewCredentialsCache(creds)
	}
	if msg.Region != "" {
		awsCfg.Region = msg.Region
	} else if s.cfg.Region != "" {
		awsCfg.Region = s.cfg.Region
	}

	client := ses.NewFromConfig(awsCfg)

	source := &s.cfg.Source
	if msg.Source != "" {
		source = &msg.Source
	}

	sourceARN := &s.cfg.SourceARN
	if msg.SourceARN != "" {
		sourceARN = &msg.SourceARN
	}

	_, err := client.SendEmail(ctx, &ses.SendEmailInput{
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
		Source:    source,
		SourceArn: sourceARN,
	})
	return err
}
