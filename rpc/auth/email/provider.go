package email

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"

	"github.com/0xsequence/ethkit/go-ethereum/common/hexutil"
	ethcrypto "github.com/0xsequence/ethkit/go-ethereum/crypto"
	"github.com/0xsequence/go-sequence/intents"
	"github.com/0xsequence/waas-authenticator/proto"
	"github.com/0xsequence/waas-authenticator/proto/builder"
	"github.com/0xsequence/waas-authenticator/rpc/attestation"
	"github.com/0xsequence/waas-authenticator/rpc/auth"
	"github.com/0xsequence/waas-authenticator/rpc/tenant"
)

// AuthProvider is a Verifier that uses a secret code, delivered to user's email address, as the auth challenge.
type AuthProvider struct {
	Sender  Sender
	Builder builder.Builder
}

func NewAuthProvider(sender Sender, builder builder.Builder) auth.Provider {
	return &AuthProvider{
		Sender:  sender,
		Builder: builder,
	}
}

func (*AuthProvider) IsEnabled(tenant *proto.TenantData) bool {
	return tenant.AuthConfig.Email.Enabled == true
}

// InitiateAuth for Email ignores any preexisting auth session data. Instead, if called multiple times, the auth session
// is replaced. This allows the user to resend the verification code in case of issues. Note that this invalidates the
// previous auth session - only the most recent one is stored and used in Verify.
func (p *AuthProvider) InitiateAuth(
	ctx context.Context,
	verifCtx *proto.VerificationContext,
	verifier string,
	sessionID string,
	storeFn auth.StoreVerificationContextFn,
) (*intents.IntentResponseAuthInitiated, error) {
	att := attestation.FromContext(ctx)
	tnt := tenant.FromContext(ctx)

	// the verifier consists of the email address and sessionID separated by ';'
	emailAddress, expectedSessionID, err := p.extractVerifier(verifier)
	if err != nil {
		return nil, err
	}
	if sessionID != expectedSessionID {
		return nil, fmt.Errorf("invalid session ID")
	}

	// TODO: validate email address

	// Retrieve the email template from the Builder.
	tplType := builder.EmailTemplateType_LOGIN
	tpl, err := p.Builder.GetEmailTemplate(ctx, tnt.ProjectID, &tplType)
	if err != nil {
		return nil, fmt.Errorf("failed to build email template: %w", err)
	}

	// generate the secret verification code to be sent to the user
	secretCode, err := randomDigits(att, 6)
	if err != nil {
		return nil, err
	}
	// client salt is sent back to the client in the intent response
	clientSalt, err := randomHex(att, 12)
	if err != nil {
		return nil, err
	}
	// server salt is sent to the WaaS API and stored in the auth session
	serverSalt, err := randomHex(att, 12)
	if err != nil {
		return nil, err
	}

	// clientAnswer is the value that we expect the client to produce
	clientAnswer := hexutil.Encode(ethcrypto.Keccak256([]byte(clientSalt + secretCode)))

	// serverAnswer is the value we compare the answer against during verification
	serverAnswer := hexutil.Encode(ethcrypto.Keccak256([]byte(serverSalt + clientAnswer)))

	// WaaS API is expected to store the answer and salt for later verification
	verifCtx = &proto.VerificationContext{
		ProjectID:    tnt.ProjectID,
		SessionID:    sessionID,
		IdentityType: proto.IdentityType_Email,
		Verifier:     verifier,
		Challenge:    &serverSalt,   // the SERVER salt is a challenge in server's context
		Answer:       &serverAnswer, // the final answer, after hashing clientAnswer with serverSalt
		ExpiresAt:    time.Now().Add(30 * time.Minute),
	}
	if err := storeFn(ctx, verifCtx); err != nil {
		return nil, err
	}

	// Build the email message. The template is expected to contain the `{auth_code}` tag to be replaced with the
	// generated secret code.
	msg := &Message{
		Recipient: emailAddress,
		Subject:   tpl.Subject,
		HTML:      strings.Replace(*tpl.Template, "{auth_code}", secretCode, 1),
		Text:      tpl.IntroText + "\n\n" + secretCode,
	}
	if err := p.Sender.Send(ctx, msg); err != nil {
		return nil, fmt.Errorf("failed to send email: %w", err)
	}

	// Client should combine the challenge from the response with the code from the email address and hash it.
	// The resulting value is the clientAnswer that is then send with the openSession intent and passed to Verify.
	res := &intents.IntentResponseAuthInitiated{
		SessionID:    verifCtx.SessionID,
		IdentityType: intents.IdentityType_Email,
		ExpiresIn:    int(time.Now().Sub(verifCtx.ExpiresAt).Seconds()),
		Challenge:    &clientSalt, // the CLIENT salt is a challenge in client's context
	}
	return res, nil
}

// Verify requires the auth session to exist as it contains the challenge and final answer. The challenge (server salt)
// from the auth session is combined with the client's answer and the resulting value compared with the final answer.
// Verify returns the identity if this is successful.
func (p *AuthProvider) Verify(ctx context.Context, verifCtx *proto.VerificationContext, sessionID string, answer string) (proto.Identity, error) {
	if verifCtx == nil {
		return proto.Identity{}, fmt.Errorf("auth session not found")
	}

	if verifCtx.Challenge == nil || verifCtx.Answer == nil {
		return proto.Identity{}, fmt.Errorf("auth session did not have challenge/answer")
	}

	// the verifier consists of the email address and sessionID separated by ';'
	emailAddress, verifierSessionID, err := p.extractVerifier(verifCtx.Verifier)
	if err != nil {
		return proto.Identity{}, err
	}
	if verifierSessionID != sessionID {
		return proto.Identity{}, fmt.Errorf("invalid session ID")
	}

	// challenge here is the server salt; combined with the client's answer and hashed it produces the serverAnswer
	serverAnswer := hexutil.Encode(ethcrypto.Keccak256([]byte(*verifCtx.Challenge + answer)))
	if serverAnswer != *verifCtx.Answer {
		return proto.Identity{}, fmt.Errorf("incorrect answer")
	}

	ident := proto.Identity{
		Type:    proto.IdentityType_Email,
		Subject: emailAddress,
		Email:   emailAddress,
	}
	return ident, nil
}

// ValidateTenant always succeeds as there are no email-specific settings to validate.
func (p *AuthProvider) ValidateTenant(ctx context.Context, tenant *proto.TenantData) error {
	return nil
}

func (p *AuthProvider) extractVerifier(verifier string) (emailAddress string, sessionID string, err error) {
	parts := strings.SplitN(verifier, ";", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid verifier")
	}
	return parts[0], parts[1], nil
}

func randomDigits(source io.Reader, n int) (string, error) {
	const digits = "0123456789"
	result := make([]byte, n)

	for i := range result {
		num, err := rand.Int(source, big.NewInt(int64(len(digits))))
		if err != nil {
			return "", err
		}
		result[i] = digits[num.Int64()]
	}

	return string(result), nil
}

func randomHex(source io.Reader, n int) (string, error) {
	b := make([]byte, n)
	if _, err := source.Read(b); err != nil {
		return "", err
	}
	return hexutil.Encode(b), nil
}
