package rpc

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/0xsequence/ethkit/ethcoder"
	"github.com/0xsequence/go-sequence/intents"
	"github.com/0xsequence/waas-authenticator/data"
	"github.com/0xsequence/waas-authenticator/proto"
	"github.com/0xsequence/waas-authenticator/rpc/attestation"
	"github.com/0xsequence/waas-authenticator/rpc/auth"
	"github.com/0xsequence/waas-authenticator/rpc/crypto"
	"github.com/0xsequence/waas-authenticator/rpc/tenant"
	"github.com/0xsequence/waas-authenticator/rpc/tracing"
	"github.com/0xsequence/waas-authenticator/rpc/waasapi"
)

func (s *RPC) RegisterSession(
	ctx context.Context, protoIntent *proto.Intent, friendlyName string,
) (*proto.Session, *proto.IntentResponse, error) {
	att := attestation.FromContext(ctx)
	tntData := tenant.FromContext(ctx)

	intent, sessionID, err := parseIntent(protoIntent)
	if err != nil {
		return nil, nil, fmt.Errorf("parse intent: %w", err)
	}

	if intent.Name != intents.IntentName_openSession {
		return nil, nil, fmt.Errorf("unexpected intent name: %q", intent.Name)
	}

	ctx, span := tracing.Intent(ctx, intent)
	defer span.End()

	intentTyped, err := intents.NewIntentTypedFromIntent[intents.IntentDataOpenSession](intent)
	if err != nil {
		return nil, nil, err
	}

	if sessionID != intentTyped.Data.SessionID {
		return nil, nil, fmt.Errorf("signing session and session to register must match")
	}

	authProvider, err := s.getAuthProvider(intentTyped.Data.IdentityType)
	if err != nil {
		return nil, nil, fmt.Errorf("get auth provider: %w", err)
	}

	sessionHash := ethcoder.Keccak256Hash([]byte(strings.ToLower(sessionID))).String()
	answer := intentTyped.Data.Answer
	if idToken := intentTyped.Data.IdToken; idToken != nil {
		answer = *idToken
	}

	var verifCtx *proto.VerificationContext
	authID := data.AuthID{
		ProjectID:    tntData.ProjectID,
		IdentityType: intentTyped.Data.IdentityType,
		Verifier:     intentTyped.Data.Verifier,
	}
	dbVerifCtx, found, err := s.VerificationContexts.Get(ctx, authID)
	if err != nil {
		return nil, nil, fmt.Errorf("getting verification context: %w", err)
	}
	if found && dbVerifCtx != nil {
		verifCtx, _, err = crypto.DecryptData[*proto.VerificationContext](ctx, dbVerifCtx.EncryptedKey, dbVerifCtx.Ciphertext, tntData.KMSKeys)
		if err != nil {
			return nil, nil, fmt.Errorf("decrypting verification context data: %w", err)
		}

		if time.Now().After(verifCtx.ExpiresAt) {
			return nil, nil, fmt.Errorf("verification context expired")
		}

		if !dbVerifCtx.CorrespondsTo(verifCtx) {
			return nil, nil, fmt.Errorf("malformed verification context data")
		}
	}

	ident, err := authProvider.Verify(ctx, verifCtx, sessionID, answer)
	if err != nil {
		if verifCtx != nil {
			now := time.Now()
			verifCtx.Attempts += 1
			verifCtx.LastAttemptAt = &now

			encryptedKey, algorithm, ciphertext, err := crypto.EncryptData(ctx, att, tntData.KMSKeys[0], verifCtx)
			if err != nil {
				return nil, nil, fmt.Errorf("encrypt data: %w", err)
			}
			if err := s.VerificationContexts.UpdateData(ctx, dbVerifCtx, encryptedKey, algorithm, ciphertext); err != nil {
				return nil, nil, fmt.Errorf("update verification context: %w", err)
			}
		}

		return nil, nil, fmt.Errorf("verifying answer: %w", err)
	}

	account, accountFound, err := s.Accounts.Get(ctx, tntData.ProjectID, ident)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to retrieve account: %w", err)
	}

	if !accountFound {
		if !intentTyped.Data.ForceCreateAccount {
			accs, err := s.Accounts.ListByEmail(ctx, tntData.ProjectID, ident.Email)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to perform email check: %w", err)
			}
			if len(accs) > 0 {
				return nil, nil, proto.ErrEmailAlreadyInUse.WithCause(fmt.Errorf("%s", accs[0].Identity.Issuer))
			}
		}

		accData := &proto.AccountData{
			ProjectID: tntData.ProjectID,
			UserID:    fmt.Sprintf("%d|%s", tntData.ProjectID, sessionHash),
			Identity:  ident.String(),
			CreatedAt: time.Now(),
		}
		encryptedKey, algorithm, ciphertext, err := crypto.EncryptData(ctx, att, tntData.KMSKeys[0], accData)
		if err != nil {
			return nil, nil, fmt.Errorf("encrypting account data: %w", err)
		}

		account = &data.Account{
			ProjectID:          tntData.ProjectID,
			Identity:           data.Identity(ident),
			UserID:             accData.UserID,
			Email:              ident.Email,
			ProjectScopedEmail: fmt.Sprintf("%d|%s", tntData.ProjectID, ident.Email),
			EncryptedKey:       encryptedKey,
			Algorithm:          algorithm,
			Ciphertext:         ciphertext,
			CreatedAt:          accData.CreatedAt,
		}
	}

	res, err := s.Wallets.RegisterSession(waasapi.Context(ctx), account.UserID, waasapi.ConvertToAPIIntent(intent))
	if err != nil {
		return nil, nil, fmt.Errorf("registering session with WaaS API: %w", err)
	}

	if !accountFound {
		if err := s.Accounts.Put(ctx, account); err != nil {
			return nil, nil, fmt.Errorf("save account: %w", err)
		}
	}

	ttl := 100 * 365 * 24 * time.Hour // TODO: should be configured somewhere, maybe per tenant?
	sessData := proto.SessionData{
		ID:        sessionID,
		ProjectID: tntData.ProjectID,
		UserID:    account.UserID,
		Identity:  ident.String(),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(ttl),
	}

	encryptedKey, algorithm, ciphertext, err := crypto.EncryptData(ctx, att, tntData.KMSKeys[0], sessData)
	if err != nil {
		return nil, convertIntentResponse(res), fmt.Errorf("encrypting session data: %w", err)
	}

	dbSess := &data.Session{
		ID:           sessionID,
		ProjectID:    tntData.ProjectID,
		UserID:       account.UserID,
		Identity:     ident.String(),
		FriendlyName: friendlyName,
		EncryptedKey: encryptedKey,
		Algorithm:    algorithm,
		Ciphertext:   ciphertext,
		RefreshedAt:  sessData.CreatedAt,
		CreatedAt:    sessData.CreatedAt,
	}

	if err := s.Sessions.Put(ctx, dbSess); err != nil {
		return nil, convertIntentResponse(res), fmt.Errorf("save session: %w", err)
	}

	retSess := &proto.Session{
		ID:           dbSess.ID,
		UserID:       dbSess.UserID,
		ProjectID:    sessData.ProjectID,
		Identity:     ident,
		FriendlyName: dbSess.FriendlyName,
		CreatedAt:    sessData.CreatedAt,
		RefreshedAt:  dbSess.RefreshedAt,
		ExpiresAt:    sessData.ExpiresAt,
	}
	return retSess, convertIntentResponse(res), nil
}

func (s *RPC) initiateAuth(
	ctx context.Context, intent *intents.IntentTyped[intents.IntentDataInitiateAuth],
) (*intents.IntentResponseAuthInitiated, error) {
	tnt := tenant.FromContext(ctx)

	authProvider, err := s.getAuthProvider(intent.Data.IdentityType)
	if err != nil {
		return nil, fmt.Errorf("get auth provider: %w", err)
	}

	if !authProvider.IsEnabled(tnt) {
		return nil, fmt.Errorf("identity type %s is unavailable", intent.Data.IdentityType)
	}

	var verifCtx *proto.VerificationContext
	authID := data.AuthID{
		ProjectID:    tnt.ProjectID,
		IdentityType: intent.Data.IdentityType,
		Verifier:     intent.Data.Verifier,
	}
	dbVerifCtx, found, err := s.VerificationContexts.Get(ctx, authID)
	if err != nil {
		return nil, fmt.Errorf("getting verification context: %w", err)
	}
	if found && dbVerifCtx != nil {
		verifCtx, _, err = crypto.DecryptData[*proto.VerificationContext](
			ctx, dbVerifCtx.EncryptedKey, dbVerifCtx.Ciphertext, tnt.KMSKeys,
		)
		if err != nil {
			return nil, fmt.Errorf("decrypting verification context data: %w", err)
		}
	}

	storeSessFn := func(ctx context.Context, verifCtx *proto.VerificationContext) error {
		att := attestation.FromContext(ctx)

		answer, challenge := "", ""
		if verifCtx.Answer != nil {
			answer = *verifCtx.Answer
		}
		if verifCtx.Challenge != nil {
			challenge = *verifCtx.Challenge
		}

		_, err = s.Wallets.InitiateAuth(waasapi.Context(ctx), waasapi.ConvertToAPIIntent(intent.ToIntent()), answer, challenge)
		if err != nil {
			return fmt.Errorf("initiating auth with WaaS API: %m", err)
		}

		encryptedKey, algorithm, ciphertext, err := crypto.EncryptData(ctx, att, tnt.KMSKeys[0], verifCtx)
		if err != nil {
			return fmt.Errorf("encrypting account data: %w", err)
		}

		dbVerifCtx := &data.VerificationContext{
			ID: data.AuthID{
				ProjectID:    tnt.ProjectID,
				IdentityType: intent.Data.IdentityType,
				Verifier:     verifCtx.Verifier,
			},
			EncryptedKey: encryptedKey,
			Algorithm:    algorithm,
			Ciphertext:   ciphertext,
		}
		if err := s.VerificationContexts.Put(ctx, dbVerifCtx); err != nil {
			return fmt.Errorf("putting verification context: %w", err)
		}
		return nil
	}

	return authProvider.InitiateAuth(ctx, verifCtx, intent.Data.Verifier, intent.Signers()[0], storeSessFn)
}

func (s *RPC) dropSession(
	ctx context.Context, sess *data.Session, intent *intents.IntentTyped[intents.IntentDataCloseSession],
) (bool, error) {
	tntData := tenant.FromContext(ctx)

	dropSess, found, err := s.Sessions.Get(ctx, tntData.ProjectID, intent.Data.SessionID)
	if err != nil || !found || sess == nil || dropSess.UserID != sess.UserID {
		return true, nil
	}

	if _, err := s.Wallets.InvalidateSession(waasapi.Context(ctx), dropSess.ID); err != nil {
		return false, fmt.Errorf("invalidating session with WaaS API: %w", err)
	}

	if err := s.Sessions.Delete(ctx, tntData.ProjectID, dropSess.ID); err != nil {
		return false, fmt.Errorf("deleting session: %w", err)
	}

	return true, nil
}

func (s *RPC) listSessions(
	ctx context.Context, sess *data.Session, intent *intents.IntentTyped[intents.IntentDataListSessions],
) ([]*proto.Session, error) {
	tntData := tenant.FromContext(ctx)

	dbSessions, err := s.Sessions.ListByUserID(ctx, sess.UserID)
	if err != nil {
		return nil, fmt.Errorf("listing DB sessions: %w", err)
	}

	out := make([]*proto.Session, len(dbSessions))
	for i, dbSess := range dbSessions {
		sessData, _, err := crypto.DecryptData[*proto.SessionData](ctx, dbSess.EncryptedKey, dbSess.Ciphertext, tntData.KMSKeys)
		if err != nil {
			return nil, fmt.Errorf("decrypting session data: %w", err)
		}

		var identity proto.Identity
		if err := identity.FromString(sessData.Identity); err != nil {
			return nil, fmt.Errorf("parsing session identity: %w", err)
		}

		out[i] = &proto.Session{
			ID:           dbSess.ID,
			UserID:       dbSess.UserID,
			ProjectID:    sessData.ProjectID,
			Identity:     identity,
			FriendlyName: dbSess.FriendlyName,
			CreatedAt:    sessData.CreatedAt,
			RefreshedAt:  dbSess.RefreshedAt,
			ExpiresAt:    sessData.ExpiresAt,
		}
	}
	return out, nil
}

func (s *RPC) getAuthProvider(identityType intents.IdentityType) (auth.Provider, error) {
	if identityType == "" {
		identityType = intents.IdentityType_None
	}

	authProvider, ok := s.AuthProviders[identityType]
	if !ok {
		return nil, fmt.Errorf("unknown identity type: %v", identityType)
	}
	return authProvider, nil
}
