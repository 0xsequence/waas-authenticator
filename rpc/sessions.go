package rpc

import (
	"context"
	"fmt"
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
		return nil, nil, err
	}

	identity, err := verifyIdentity(ctx, s.HTTPClient, payload.IDToken)
	if err != nil {
		return nil, nil, err
	}

	if payload.ProjectID != identity.ProjectID || payload.ProjectID != tntData.ProjectID {
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

	// TODO: validate that idToken and session address from IntentJSON match the ones in payload
	// TODO: *OR* we don't need them in payload, we can get them directly from the intent
	res, err := s.Wallets.RegisterSession(waasCtx, identity.String(), payload.IntentJSON)
	if err != nil {
		return nil, nil, err
	}

	ttl := 100 * 365 * 24 * time.Hour // TODO: should be configured somewhere, maybe per tenant?
	sessData := proto.SessionData{
		Address:   addr,
		ProjectID: identity.ProjectID,
		Issuer:    identity.Issuer,
		Subject:   identity.Subject,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(ttl),
	}

	encryptedKey, algorithm, ciphertext, err := crypto.EncryptData(ctx, att, tntData.SessionKeys[0], sessData)
	if err != nil {
		return nil, res.Data, fmt.Errorf("encrypting session data: %w", err)
	}

	dbSess := &data.Session{
		ID:           addr.String(),
		ProjectID:    identity.ProjectID,
		UserID:       identity.String(),
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
		Issuer:       sessData.Issuer,
		Subject:      sessData.Subject,
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
		return false, err
	}

	_, currentSessData, err := s.verifySession(ctx, payload.SessionID, payloadBytes, payloadSig)
	if err != nil {
		return false, err
	}

	dbSess, found, err := s.Sessions.Get(ctx, tntData.ProjectID, payload.DropSessionID)
	if err != nil || !found || dbSess.UserID != currentSessData.Identity().String() {
		return false, fmt.Errorf("session not found")
	}

	waasCtx, err := waasContext(ctx)
	if err != nil {
		return false, err
	}

	if _, err := s.Wallets.InvalidateSession(waasCtx, payload.DropSessionID); err != nil {
		return false, err
	}

	if err := s.Sessions.Delete(ctx, tntData.ProjectID, dbSess.ID); err != nil {
		return false, err
	}

	return true, nil
}

func (s *RPC) ListSessions(ctx context.Context, encryptedPayloadKey string, payloadCiphertext string, payloadSig string) ([]*proto.Session, error) {
	tntData := tenant.FromContext(ctx)

	payload, payloadBytes, err := crypto.DecryptPayload[*proto.ListSessionsPayload](ctx, tntData, encryptedPayloadKey, payloadCiphertext)
	if err != nil {
		return nil, err
	}

	_, sessData, err := s.verifySession(ctx, payload.SessionID, payloadBytes, payloadSig)
	if err != nil {
		return nil, err
	}

	dbSessions, err := s.Sessions.ListByUserID(ctx, sessData.Identity().String())
	if err != nil {
		return nil, err
	}

	out := make([]*proto.Session, len(dbSessions))
	for i, dbSess := range dbSessions {
		sessData, _, err := crypto.DecryptData[*proto.SessionData](ctx, dbSess.EncryptedKey, dbSess.Ciphertext, tntData.SessionKeys)
		if err != nil {
			return nil, err
		}

		out[i] = &proto.Session{
			ID:           dbSess.ID,
			Address:      sessData.Address,
			UserID:       dbSess.UserID,
			ProjectID:    sessData.ProjectID,
			Issuer:       sessData.Issuer,
			Subject:      sessData.Subject,
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
