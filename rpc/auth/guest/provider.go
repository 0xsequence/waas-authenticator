package guest

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/0xsequence/ethkit/go-ethereum/common/hexutil"
	ethcrypto "github.com/0xsequence/ethkit/go-ethereum/crypto"
	"github.com/0xsequence/go-sequence/intents"
	"github.com/0xsequence/waas-authenticator/proto"
	"github.com/0xsequence/waas-authenticator/rpc/attestation"
	"github.com/0xsequence/waas-authenticator/rpc/auth"
	"github.com/0xsequence/waas-authenticator/rpc/tenant"
)

type AuthProvider struct{}

func NewAuthProvider() auth.Provider {
	return &AuthProvider{}
}

func (AuthProvider) IsEnabled(tenant *proto.TenantData) bool {
	return tenant.AuthConfig.Guest.Enabled == true
}

func (p AuthProvider) InitiateAuth(
	ctx context.Context,
	verifCtx *proto.VerificationContext,
	verifier string,
	sessionID string,
	storeFn auth.StoreVerificationContextFn,
) (*intents.IntentResponseAuthInitiated, error) {
	att := attestation.FromContext(ctx)
	tnt := tenant.FromContext(ctx)

	if verifier != sessionID {
		return nil, fmt.Errorf("invalid session ID")
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
	clientAnswer := hexutil.Encode(ethcrypto.Keccak256([]byte(clientSalt + verifier)))

	// serverAnswer is the value we compare the answer against during verification
	serverAnswer := hexutil.Encode(ethcrypto.Keccak256([]byte(serverSalt + clientAnswer)))

	verifCtx = &proto.VerificationContext{
		ProjectID:    tnt.ProjectID,
		SessionID:    sessionID,
		IdentityType: proto.IdentityType_Guest,
		Verifier:     verifier,
		Challenge:    &serverSalt,   // the SERVER salt is a challenge in server's context
		Answer:       &serverAnswer, // the final answer, after hashing clientAnswer with serverSalt
		ExpiresAt:    time.Now().Add(5 * time.Minute),
	}
	if err := storeFn(ctx, verifCtx); err != nil {
		return nil, err
	}

	// Client should combine the challenge from the response with the session ID and hash it.
	// The resulting value is the clientAnswer that is then send with the openSession intent and passed to Verify.
	res := &intents.IntentResponseAuthInitiated{
		SessionID:    verifCtx.SessionID,
		IdentityType: intents.IdentityType_Guest,
		ExpiresIn:    int(time.Now().Sub(verifCtx.ExpiresAt).Seconds()),
		Challenge:    &clientSalt, // the CLIENT salt is a challenge in client's context
	}
	return res, nil
}

func (p AuthProvider) Verify(ctx context.Context, verifCtx *proto.VerificationContext, sessionID string, answer string) (proto.Identity, error) {
	if verifCtx == nil {
		return proto.Identity{}, fmt.Errorf("verification context not found")
	}

	if verifCtx.Challenge == nil || verifCtx.Answer == nil {
		return proto.Identity{}, fmt.Errorf("verification context did not have challenge/answer")
	}

	if verifCtx.Verifier != sessionID {
		return proto.Identity{}, fmt.Errorf("invalid session ID")
	}

	// challenge here is the server salt; combined with the client's answer and hashed it produces the serverAnswer
	serverAnswer := hexutil.Encode(ethcrypto.Keccak256([]byte(*verifCtx.Challenge + answer)))
	if serverAnswer != *verifCtx.Answer {
		return proto.Identity{}, fmt.Errorf("incorrect answer")
	}

	ident := proto.Identity{
		Type:    proto.IdentityType_Guest,
		Subject: sessionID,
	}
	return ident, nil
}

func (p AuthProvider) ValidateTenant(ctx context.Context, tenant *proto.TenantData) error {
	return nil
}

func randomHex(source io.Reader, n int) (string, error) {
	b := make([]byte, n)
	if _, err := source.Read(b); err != nil {
		return "", err
	}
	return hexutil.Encode(b), nil
}
