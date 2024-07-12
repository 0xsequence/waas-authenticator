package rpc

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/0xsequence/go-sequence/intents"
	"github.com/0xsequence/waas-authenticator/data"
	"github.com/0xsequence/waas-authenticator/proto"
	"github.com/0xsequence/waas-authenticator/rpc/attestation"
	"github.com/0xsequence/waas-authenticator/rpc/crypto"
	"github.com/0xsequence/waas-authenticator/rpc/tenant"
	"github.com/0xsequence/waas-authenticator/rpc/waasapi"
)

func (s *RPC) listAccounts(
	ctx context.Context, sess *data.Session, intent *intents.IntentTyped[intents.IntentDataListAccounts],
) ([]*intents.Account, error) {
	tntData := tenant.FromContext(ctx)

	dbAccounts, err := s.Accounts.ListByUserID(ctx, sess.UserID)
	if err != nil {
		return nil, fmt.Errorf("listing DB accounts: %w", err)
	}

	out := make([]*intents.Account, len(dbAccounts))
	for i, dbAcc := range dbAccounts {
		accData, _, err := crypto.DecryptData[*proto.AccountData](ctx, dbAcc.EncryptedKey, dbAcc.Ciphertext, tntData.KMSKeys)
		if err != nil {
			return nil, fmt.Errorf("decrypting account data: %w", err)
		}

		var identity proto.Identity
		if err := identity.FromString(accData.Identity); err != nil {
			return nil, fmt.Errorf("parsing account identity: %w", err)
		}

		out[i] = &intents.Account{
			ID:     identity.String(),
			Type:   intents.IdentityType(identity.Type),
			Issuer: &identity.Issuer,
		}
		if dbAcc.Email != "" {
			out[i].Email = &dbAcc.Email
		}
	}
	return out, nil
}

func (s *RPC) federateAccount(
	ctx context.Context, sess *data.Session, intent *intents.IntentTyped[intents.IntentDataFederateAccount],
) (*intents.Account, error) {
	att := attestation.FromContext(ctx)
	tntData := tenant.FromContext(ctx)

	if intent.Data.SessionID != sess.ID {
		return nil, proto.ErrWebrpcBadRequest.WithCausef("sessionId mismatch")
	}

	authProvider, err := s.getAuthProvider(intent.Data.IdentityType)
	if err != nil {
		return nil, proto.ErrWebrpcBadRequest.WithCausef("get auth provider: %w", err)
	}

	if intent.Data.IdentityType == intents.IdentityType_Guest {
		return nil, proto.ErrWebrpcBadRequest.WithCausef("cannot federate a guest account")
	}

	var verifCtx *proto.VerificationContext
	authID := data.AuthID{
		ProjectID:    tntData.ProjectID,
		IdentityType: intent.Data.IdentityType,
		Verifier:     intent.Data.Verifier,
	}
	dbVerifCtx, found, err := s.VerificationContexts.Get(ctx, authID)
	if err != nil {
		return nil, proto.ErrWebrpcInternalError.WithCausef("getting verification context: %w", err)
	}
	if found && dbVerifCtx != nil {
		verifCtx, _, err = crypto.DecryptData[*proto.VerificationContext](ctx, dbVerifCtx.EncryptedKey, dbVerifCtx.Ciphertext, tntData.KMSKeys)
		if err != nil {
			return nil, proto.ErrWebrpcInternalError.WithCausef("decrypting verification context data: %w", err)
		}

		if time.Now().After(verifCtx.ExpiresAt) {
			return nil, proto.ErrChallengeExpired
		}

		if !dbVerifCtx.CorrespondsTo(verifCtx) {
			return nil, proto.ErrWebrpcInternalError.WithCausef("malformed verification context data")
		}
	}

	ident, err := authProvider.Verify(ctx, verifCtx, sess.ID, intent.Data.Answer)
	if err != nil {
		if verifCtx != nil {
			now := time.Now()
			verifCtx.Attempts += 1
			verifCtx.LastAttemptAt = &now

			encryptedKey, algorithm, ciphertext, err := crypto.EncryptData(ctx, att, tntData.KMSKeys[0], verifCtx)
			if err != nil {
				return nil, proto.ErrWebrpcInternalError.WithCausef("encrypt data: %w", err)
			}
			if err := s.VerificationContexts.UpdateData(ctx, dbVerifCtx, encryptedKey, algorithm, ciphertext); err != nil {
				return nil, proto.ErrWebrpcInternalError.WithCausef("update verification context: %w", err)
			}
		}

		var wErr proto.WebRPCError
		if errors.As(err, &wErr) {
			return nil, wErr
		}
		return nil, proto.ErrAnswerIncorrect.WithCausef("verifying answer: %w", err)
	}

	_, found, err = s.Accounts.Get(ctx, tntData.ProjectID, ident)
	if err != nil {
		return nil, proto.ErrWebrpcInternalError.WithCausef("retrieving account: %w", err)
	}
	if found {
		return nil, proto.ErrAccountAlreadyLinked
	}

	accData := &proto.AccountData{
		ProjectID: tntData.ProjectID,
		UserID:    sess.UserID,
		Identity:  ident.String(),
		CreatedAt: time.Now(),
	}

	encryptedKey, algorithm, ciphertext, err := crypto.EncryptData(ctx, att, tntData.KMSKeys[0], accData)
	if err != nil {
		return nil, proto.ErrWebrpcInternalError.WithCausef("encrypting account data: %w", err)
	}

	account := &data.Account{
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

	if _, err := s.Wallets.FederateAccount(waasapi.Context(ctx), account.UserID, waasapi.ConvertToAPIIntent(intent.ToIntent())); err != nil {
		return nil, proto.ErrWebrpcInternalError.WithCausef("creating account with WaaS API: %w", err)
	}

	if err := s.Accounts.Put(ctx, account); err != nil {
		return nil, proto.ErrWebrpcInternalError.WithCausef("save account: %w", err)
	}

	outAcc := &intents.Account{
		ID:     ident.String(),
		Type:   intents.IdentityType(ident.Type),
		Issuer: &ident.Issuer,
	}
	if ident.Email != "" {
		outAcc.Email = &ident.Email
	}
	return outAcc, nil
}

func (s *RPC) removeAccount(
	ctx context.Context, sess *data.Session, intent *intents.IntentTyped[intents.IntentDataRemoveAccount],
) error {
	tntData := tenant.FromContext(ctx)

	if sess.Identity == intent.Data.AccountID {
		return fmt.Errorf("cannot remove current account")
	}

	var currentIdentity proto.Identity
	if err := currentIdentity.FromString(sess.Identity); err != nil {
		return err
	}

	_, found, err := s.Accounts.Get(ctx, tntData.ProjectID, currentIdentity)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("current account not found")
	}

	var identityToRemove proto.Identity
	if err := identityToRemove.FromString(intent.Data.AccountID); err != nil {
		return err
	}

	accToRemove, found, err := s.Accounts.Get(ctx, tntData.ProjectID, identityToRemove)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("account to remove not found")
	}

	accData, _, err := crypto.DecryptData[*proto.AccountData](ctx, accToRemove.EncryptedKey, accToRemove.Ciphertext, tntData.KMSKeys)
	if err != nil {
		return fmt.Errorf("decrypting account data: %w", err)
	}

	if accData.UserID != sess.UserID || accData.Identity != identityToRemove.String() {
		return fmt.Errorf("invalid account")
	}

	_, err = s.Wallets.RemoveAccount(waasapi.Context(ctx), waasapi.ConvertToAPIIntent(intent.ToIntent()))
	if err != nil {
		return err
	}

	if err := s.deleteAccountSessions(ctx, tntData.ProjectID, sess.UserID, identityToRemove); err != nil {
		return err
	}

	if err := s.Accounts.Delete(ctx, tntData.ProjectID, identityToRemove); err != nil {
		return err
	}

	return nil
}

func (s *RPC) deleteAccountSessions(ctx context.Context, projectID uint64, userID string, identity proto.Identity) error {
	sessions, err := s.Sessions.ListByUserID(ctx, userID)
	if err != nil {
		return err
	}
	fmt.Printf("sessions of user %s: %+v\n", userID, sessions)

	// TODO: make the removal of all sessions more efficient
	// we can achieve it by paginating over sessions (adding an index would help here) and then batching deletes
	// 25 at a time.
	var errs []error
	for _, sess := range sessions {
		if sess.Identity != identity.String() {
			fmt.Println("deleteAccountSessions: skipping session", sess.Identity)
			continue
		}

		if err := s.Sessions.Delete(ctx, projectID, sess.ID); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("failed to delete %d sessions", len(errs))
	}
	return nil
}
