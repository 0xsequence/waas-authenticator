package rpc

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/0xsequence/ethkit/ethwallet"
	"github.com/0xsequence/ethkit/go-ethereum/common"
	"github.com/0xsequence/waas-authenticator/data"
	"github.com/0xsequence/waas-authenticator/proto"
	"github.com/0xsequence/waas-authenticator/rpc/attestation"
	"github.com/0xsequence/waas-authenticator/rpc/crypto"
	"github.com/0xsequence/waas-authenticator/rpc/tenant"
)

func (s *RPC) RegisterSession(ctx context.Context, encryptedPayloadKey string, payloadCiphertext string, payloadSig string) (*proto.Session, any, error) {
	att := attestation.FromContext(ctx)
	tntData := tenant.FromContext(ctx)

	payload, payloadBytes, err := crypto.DecryptPayload[*proto.RegisterSessionPayload](ctx, tntData, encryptedPayloadKey, payloadCiphertext)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypting payload: %w", err)
	}

	identity, err := verifyIdentity(ctx, s.HTTPClient, payload.IDToken, payload.SessionAddress)
	if err != nil {
		return nil, nil, fmt.Errorf("verifying identity: %w", err)
	}

	if payload.ProjectID != tntData.ProjectID {
		return nil, nil, fmt.Errorf("tenant mismatch")
	}

	if !common.IsHexAddress(payload.SessionAddress) {
		return nil, nil, fmt.Errorf("sessionAddress is invalid")
	}

	addr := common.HexToAddress(payload.SessionAddress)
	valid, err := ethwallet.ValidateEthereumSignature(addr.String(), payloadBytes, payloadSig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to validate signature: %w", err)
	}
	if !valid {
		return nil, nil, fmt.Errorf("signature is invalid")
	}

	waasCtx, err := waasContext(ctx)
	if err != nil {
		return nil, nil, err
	}

	account, accountFound, err := s.Accounts.Get(ctx, tntData.ProjectID, identity)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to retrieve account: %w", err)
	}

	if !accountFound {
		accData := &proto.AccountData{
			ProjectID: tntData.ProjectID,
			UserID:    fmt.Sprintf("%d|%s", tntData.ProjectID, strings.ToLower(addr.String())),
			Identity:  identity.String(),
			CreatedAt: time.Now(),
		}
		encryptedKey, algorithm, ciphertext, err := crypto.EncryptData(ctx, att, tntData.SessionKeys[0], accData)
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

	res, err := s.Wallets.RegisterSession(waasCtx, account.UserID, payload.IntentJSON)
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
		Address:   addr,
		ProjectID: tntData.ProjectID,
		UserID:    account.UserID,
		Identity:  identity.String(),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(ttl),
	}

	encryptedKey, algorithm, ciphertext, err := crypto.EncryptData(ctx, att, tntData.SessionKeys[0], sessData)
	if err != nil {
		return nil, res.Data, fmt.Errorf("encrypting session data: %w", err)
	}

	dbSess := &data.Session{
		ID:           addr.String(),
		ProjectID:    tntData.ProjectID,
		UserID:       account.UserID,
		Identity:     identity.String(),
		FriendlyName: payload.FriendlyName,
		EncryptedKey: encryptedKey,
		Algorithm:    algorithm,
		Ciphertext:   ciphertext,
		RefreshedAt:  sessData.CreatedAt,
		CreatedAt:    sessData.CreatedAt,
	}

	if err := s.Sessions.Put(ctx, dbSess); err != nil {
		return nil, res.Data, fmt.Errorf("save session: %w", err)
	}

	retSess := &proto.Session{
		ID:           dbSess.ID,
		Address:      sessData.Address,
		UserID:       dbSess.UserID,
		ProjectID:    sessData.ProjectID,
		Identity:     identity,
		FriendlyName: dbSess.FriendlyName,
		CreatedAt:    sessData.CreatedAt,
		RefreshedAt:  dbSess.RefreshedAt,
		ExpiresAt:    sessData.ExpiresAt,
	}
	return retSess, res.Data, nil
}

func (s *RPC) DropSession(ctx context.Context, encryptedPayloadKey string, payloadCiphertext string, payloadSig string) (bool, error) {
	tntData := tenant.FromContext(ctx)

	payload, payloadBytes, err := crypto.DecryptPayload[*proto.DropSessionPayload](ctx, tntData, encryptedPayloadKey, payloadCiphertext)
	if err != nil {
		return false, fmt.Errorf("decrypting payload: %w", err)
	}

	_, currentSessData, err := s.verifySession(ctx, payload.SessionID, payloadBytes, payloadSig)
	if err != nil {
		return false, fmt.Errorf("verifying session: %w", err)
	}

	dbSess, found, err := s.Sessions.Get(ctx, tntData.ProjectID, payload.DropSessionID)
	if err != nil || !found || dbSess.UserID != currentSessData.UserID {
		return false, fmt.Errorf("session not found")
	}

	waasCtx, err := waasContext(ctx)
	if err != nil {
		return false, err
	}

	if _, err := s.Wallets.InvalidateSession(waasCtx, payload.DropSessionID); err != nil {
		return false, fmt.Errorf("invalidating session with WaaS API: %w", err)
	}

	if err := s.Sessions.Delete(ctx, tntData.ProjectID, dbSess.ID); err != nil {
		return false, fmt.Errorf("deleting session: %w", err)
	}

	return true, nil
}

func (s *RPC) ListSessions(ctx context.Context, encryptedPayloadKey string, payloadCiphertext string, payloadSig string) ([]*proto.Session, error) {
	tntData := tenant.FromContext(ctx)

	payload, payloadBytes, err := crypto.DecryptPayload[*proto.ListSessionsPayload](ctx, tntData, encryptedPayloadKey, payloadCiphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypting payload: %w", err)
	}

	_, sessData, err := s.verifySession(ctx, payload.SessionID, payloadBytes, payloadSig)
	if err != nil {
		return nil, fmt.Errorf("verifying session: %w", err)
	}

	dbSessions, err := s.Sessions.ListByUserID(ctx, sessData.UserID)
	if err != nil {
		return nil, fmt.Errorf("listing DB sessions: %w", err)
	}

	out := make([]*proto.Session, len(dbSessions))
	for i, dbSess := range dbSessions {
		sessData, _, err := crypto.DecryptData[*proto.SessionData](ctx, dbSess.EncryptedKey, dbSess.Ciphertext, tntData.SessionKeys)
		if err != nil {
			return nil, fmt.Errorf("decrypting session data: %w", err)
		}

		var identity proto.Identity
		if err := identity.FromString(sessData.Identity); err != nil {
			return nil, fmt.Errorf("parsing session identity: %w", err)
		}

		out[i] = &proto.Session{
			ID:           dbSess.ID,
			Address:      sessData.Address,
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

func (s *RPC) verifySession(ctx context.Context, sessionID string, payloadBytes []byte, payloadSig string) (*data.Session, *proto.SessionData, error) {
	tntData := tenant.FromContext(ctx)

	sess, found, err := s.Sessions.Get(ctx, tntData.ProjectID, sessionID)
	if err != nil || !found {
		return nil, nil, fmt.Errorf("session invalid or not found")
	}

	sessData, _, err := crypto.DecryptData[*proto.SessionData](ctx, sess.EncryptedKey, sess.Ciphertext, tntData.SessionKeys)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt session: %w", err)
	}

	valid, err := ethwallet.ValidateEthereumSignature(sessData.Address.String(), payloadBytes, payloadSig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to validate signature: %w", err)
	}
	if !valid {
		return nil, nil, fmt.Errorf("signature is invalid")
	}

	return sess, sessData, nil
}
