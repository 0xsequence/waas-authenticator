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

func (s *RPC) RegisterSession(
	ctx context.Context, protoIntent *proto.Intent, friendlyName string,
) (*proto.Session, *proto.IntentResponse, error) {
	att := attestation.FromContext(ctx)
	tntData := tenant.FromContext(ctx)

	intent, sessionID, err := parseIntent(protoIntent)
	if err != nil {
		return nil, nil, fmt.Errorf("parse intent: %w", err)
	}

	if intent.Name != intents.IntentNameOpenSession {
		return nil, nil, fmt.Errorf("unexpected intent name: %q", intent.Name)
	}

	intentTyped, err := intents.NewIntentTypedFromIntent[intents.IntentDataOpenSession](intent)
	if err != nil {
		return nil, nil, err
	}

	if sessionID != intentTyped.Data.SessionId {
		return nil, nil, fmt.Errorf("signing session and session to register must match")
	}

	idToken := intentTyped.Data.IdToken
	if idToken == nil || *idToken == "" {
		return nil, nil, fmt.Errorf("idToken is required")
	}

	sessionHash := ethcoder.Keccak256Hash([]byte(strings.ToLower(sessionID))).String()
	identity, err := verifyIdentity(ctx, s.HTTPClient, *idToken, sessionHash)
	if err != nil {
		return nil, nil, fmt.Errorf("verifying identity: %w", err)
	}

	account, accountFound, err := s.Accounts.Get(ctx, tntData.ProjectID, identity)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to retrieve account: %w", err)
	}

	if !accountFound {
		accData := &proto.AccountData{
			ProjectID: tntData.ProjectID,
			UserID:    fmt.Sprintf("%d|%s", tntData.ProjectID, sessionHash),
			Identity:  identity.String(),
			CreatedAt: time.Now(),
		}
		encryptedKey, algorithm, ciphertext, err := crypto.EncryptData(ctx, att, tntData.KMSKeys[0], accData)
		if err != nil {
			return nil, nil, fmt.Errorf("encrypting account data: %w", err)
		}

		account = &data.Account{
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
	}

	res, err := s.Wallets.RegisterSession(waasContext(ctx), account.UserID, convertToAPIIntent(intent))
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
		Identity:  identity.String(),
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
		Identity:     identity.String(),
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
		Identity:     identity,
		FriendlyName: dbSess.FriendlyName,
		CreatedAt:    sessData.CreatedAt,
		RefreshedAt:  dbSess.RefreshedAt,
		ExpiresAt:    sessData.ExpiresAt,
	}
	return retSess, convertIntentResponse(res), nil
}

func (s *RPC) dropSession(
	ctx context.Context, sess *data.Session, intent *intents.IntentTyped[intents.IntentDataCloseSession],
) (bool, error) {
	tntData := tenant.FromContext(ctx)

	dropSess, found, err := s.Sessions.Get(ctx, tntData.ProjectID, intent.Data.SessionId)
	if err != nil || !found || dropSess.UserID != sess.UserID {
		return false, fmt.Errorf("session not found")
	}

	if _, err := s.Wallets.InvalidateSession(waasContext(ctx), dropSess.ID); err != nil {
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
