package email

import (
	"context"
)

type Message struct {
	Recipient     string
	Subject       string
	HTML          string
	Text          string
	Source        string
	SourceARN     string
	AccessRoleARN string
}

type Sender interface {
	Send(ctx context.Context, message *Message) error
}
