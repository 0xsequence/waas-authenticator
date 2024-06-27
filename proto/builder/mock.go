package builder

import (
	"context"
	"fmt"
)

type Mock struct{}

func NewMock() Builder {
	return Mock{}
}

func (m Mock) GetEmailTemplate(ctx context.Context, projectID uint64, templateType *EmailTemplateType) (*EmailTemplate, error) {
	template := "Your login code: {auth_code}"
	return &EmailTemplate{
		TemplateType: templateType,
		IntroText:    "Your login code",
		Subject:      fmt.Sprintf("Login code for %d", projectID),
		Template:     &template,
	}, nil
}

var _ Builder = (*Mock)(nil)
