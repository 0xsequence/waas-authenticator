package rpc

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/0xsequence/ethkit/ethwallet"
	"github.com/0xsequence/ethkit/go-ethereum/common"
	"github.com/0xsequence/waas-authenticator/data"
	"github.com/0xsequence/waas-authenticator/proto"
	"github.com/0xsequence/waas-authenticator/rpc/crypto"
	"github.com/0xsequence/waas-authenticator/rpc/tenant"
)

func (s *RPC) RegisterSession(ctx context.Context, encryptedPayloadKey string, payloadCiphertext string, payloadSig string) (*proto.Session, any, error) {
	tntData := tenant.FromContext(ctx)

	payload, payloadBytes, err := crypto.DecryptPayload[*proto.RegisterSessionPayload](ctx, tntData, encryptedPayloadKey, payloadCiphertext)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypting payload: %w", err)
	}

	addr := common.HexToAddress(payload.SessionAddress)
	valid, err := ethwallet.ValidateEthereumSignature(addr.String(), payloadBytes, payloadSig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to validate signature: %w", err)
	}
	if !valid {
		return nil, nil, fmt.Errorf("signature is invalid")
	}

	var intent proto.Intent
	if err := json.Unmarshal([]byte(payload.IntentJSON), &intent); err != nil {
		return nil, nil, err
	}

	return s.RegisterSessionV1(ctx, &intent, payload.FriendlyName)
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

	if _, err := s.Wallets.InvalidateSession(waasContext(ctx), payload.DropSessionID); err != nil {
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

func (s *RPC) GetAddress(ctx context.Context, encryptedPayloadKey string, payloadCiphertext string, payloadSig string) (string, error) {
	tntData := tenant.FromContext(ctx)

	payload, payloadBytes, err := crypto.DecryptPayload[*proto.GetAddressPayload](ctx, tntData, encryptedPayloadKey, payloadCiphertext)
	if err != nil {
		return "", fmt.Errorf("decrypting payload: %w", err)
	}

	_, sessData, err := s.verifySession(ctx, payload.SessionID, payloadBytes, payloadSig)
	if err != nil {
		return "", fmt.Errorf("verifying session: %w", err)
	}

	return AddressForUser(ctx, tntData, sessData.UserID)
}

func (s *RPC) SendIntent(ctx context.Context, encryptedPayloadKey string, payloadCiphertext string, payloadSig string) (string, interface{}, error) {
	tntData := tenant.FromContext(ctx)

	payload, _, err := crypto.DecryptPayload[*proto.SendIntentPayload](ctx, tntData, encryptedPayloadKey, payloadCiphertext)
	if err != nil {
		return "", nil, fmt.Errorf("decrypting payload: %w", err)
	}

	var intent proto.Intent
	if err := json.Unmarshal([]byte(payload.IntentJSON), &intent); err != nil {
		return "", nil, err
	}
	return s.SendIntentV1(ctx, &intent)
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
