package auth

import (
	"context"

	"github.com/0xsequence/go-sequence/intents"
	"github.com/0xsequence/waas-authenticator/proto"
)

type StoreVerificationContextFn func(context.Context, *proto.VerificationContext) error

type Provider interface {
	// InitiateAuth is called as the first step in the authentication process, triggered by the initiateAuth intent.
	// Provider should use this to prepare the challenge and store it in a verification context for later Verify use,
	// if needed, using the function passed to it.
	//
	// Optionally, InitiateAuth might receive a non-nil verifCtx if a VerificationContext already exists for this
	// specific project/identityType/verifier combination. Provider might decide to either ignore it, override the
	// verification context or return an error.
	InitiateAuth(
		ctx context.Context,
		verifCtx *proto.VerificationContext,
		verifier string,
		intent *intents.Intent,
		storeFn StoreVerificationContextFn,
	) (*intents.IntentResponseAuthInitiated, error)

	// Verify is triggered by the openSession intent. Provider should use the VerificationContext and answer passed to
	// it to validate the user's sign in attempt. Returning an Identity with no error will cause a valid session to be
	// opened. Otherwise, the VerificationContext is updated by the caller, increasing the Attempts count.
	//
	// The VerificationContext might be nil if the user sent the openSession intent without sending initiateAuth first.
	Verify(
		ctx context.Context, verifCtx *proto.VerificationContext, sessionID string, answer string,
	) (proto.Identity, error)

	// ValidateTenant is called by the admin service whenever the Tenant is created or updated. Provider should verify
	// that the configuration is correct and valid for the specific identity type.
	ValidateTenant(ctx context.Context, tenant *proto.TenantData) error
}
