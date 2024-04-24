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
	"github.com/0xsequence/waas-authenticator/rpc/crypto"
	"github.com/0xsequence/waas-authenticator/rpc/tenant"
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
			Type:   intents.IdentityType(identity.Type.String()),
			Issuer: identity.Issuer,
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
		return nil, fmt.Errorf("sessionId mismatch")
	}

	sessionHash := ethcoder.Keccak256Hash([]byte(strings.ToLower(sess.ID))).String()
	identity, err := verifyIdentity(ctx, s.HTTPClient, intent.Data.IdToken, sessionHash)
	if err != nil {
		return nil, fmt.Errorf("verifying identity: %w", err)
	}

	_, found, err := s.Accounts.Get(ctx, tntData.ProjectID, identity)
	if err != nil {
		return nil, fmt.Errorf("retrieving account: %w", err)
	}
	if found {
		return nil, fmt.Errorf("account already exists")
	}

	accData := &proto.AccountData{
		ProjectID: tntData.ProjectID,
		UserID:    sess.UserID,
		Identity:  identity.String(),
		CreatedAt: time.Now(),
	}

	encryptedKey, algorithm, ciphertext, err := crypto.EncryptData(ctx, att, tntData.KMSKeys[0], accData)
	if err != nil {
		return nil, fmt.Errorf("encrypting account data: %w", err)
	}

	account := &data.Account{
		ProjectID:          tntData.ProjectID,
		Identity:           data.Identity(identity),
		UserID:             accData.UserID,
		Email:              identity.Email,
		ProjectScopedEmail: fmt.Sprintf("%d|%s", tntData.ProjectID, identity.Email),
		EncryptedKey:       encryptedKey,
		Algorithm:          algorithm,
		Ciphertext:         ciphertext,
		CreatedAt:          accData.CreatedAt,
	}

	if _, err := s.Wallets.FederateAccount(waasContext(ctx), account.UserID, convertToAPIIntent(intent.ToIntent())); err != nil {
		return nil, fmt.Errorf("creating account with WaaS API: %w", err)
	}

	if err := s.Accounts.Put(ctx, account); err != nil {
		return nil, fmt.Errorf("save account: %w", err)
	}

	outAcc := &intents.Account{
		ID:     identity.String(),
		Type:   intents.IdentityType(identity.Type),
		Issuer: identity.Issuer,
	}
	if identity.Email != "" {
		outAcc.Email = &identity.Email
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

	_, err = s.Wallets.RemoveAccount(waasContext(ctx), convertToAPIIntent(intent.ToIntent()))
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

		fmt.Println("deleteAccountSessions: deleting", sess.Identity, identity.String())

		if err := s.Sessions.Delete(ctx, projectID, sess.ID); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("failed to delete %d sessions", len(errs))
	}
	return nil
}
