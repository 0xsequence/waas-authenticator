package email

import (
	"testing"

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
