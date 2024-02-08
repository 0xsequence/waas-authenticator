package rpc

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/0xsequence/ethkit/go-ethereum/common"
	"github.com/0xsequence/go-sequence/intents/packets"
	"github.com/0xsequence/waas-authenticator/data"
	"github.com/0xsequence/waas-authenticator/proto"
	"github.com/0xsequence/waas-authenticator/rpc/attestation"
	"github.com/0xsequence/waas-authenticator/rpc/crypto"
	"github.com/0xsequence/waas-authenticator/rpc/tenant"
)

func (s *RPC) RegisterSessionV1(ctx context.Context, intent *proto.Intent, friendlyName string) (*proto.Session, any, error) {
	att := attestation.FromContext(ctx)
	tntData := tenant.FromContext(ctx)

	payload, err := proto.ParseIntentWithPacket(intent, &packets.OpenSessionPacket{})
	if err != nil {
		return nil, nil, fmt.Errorf("parse intent: %w", err)
	}

	if payload.Session != payload.Packet.Session {
		return nil, nil, fmt.Errorf("signing session and session to register must match")
	}

	identity, err := verifyIdentity(ctx, s.HTTPClient, payload.Packet.Proof.IDToken, payload.Session)
	if err != nil {
		return nil, nil, fmt.Errorf("verifying identity: %w", err)
	}

	if !common.IsHexAddress(payload.Session) {
		return nil, nil, fmt.Errorf("session is invalid")
	}

	account, accountFound, err := s.Accounts.Get(ctx, tntData.ProjectID, identity)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to retrieve account: %w", err)
	}

	addr := common.HexToAddress(payload.Session)

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

	res, err := s.Wallets.RegisterSession(waasContext(ctx), account.UserID, payload.IntentJSON)
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
		FriendlyName: friendlyName,
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

func (s *RPC) dropSession(
	ctx context.Context, sess *data.Session, payload *proto.Payload[*packets.CloseSessionPacket],
) (bool, error) {
	tntData := tenant.FromContext(ctx)

	dropSess, found, err := s.Sessions.Get(ctx, tntData.ProjectID, payload.Packet.Session)
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

func (s *RPC) listSessions(ctx context.Context, sess *data.Session, payload *proto.Payload[*proto.ListSessionsPacket]) ([]*proto.Session, error) {
	tntData := tenant.FromContext(ctx)

	dbSessions, err := s.Sessions.ListByUserID(ctx, sess.UserID)
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
