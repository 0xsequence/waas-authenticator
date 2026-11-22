package rpc

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/0xsequence/ethkit/go-ethereum/common"
	"github.com/0xsequence/go-sequence/intents"
	"github.com/0xsequence/waas-authenticator/data"
	"github.com/0xsequence/waas-authenticator/proto"
)

// checkIntentWallet rejects an intent that names a wallet other than the
// session user's own. Intents act on the caller's wallet only, and the
// authenticator signs with the tenant's parent key for whichever wallet the
// intent names, so it must not rely on downstream services for this check.
func checkIntentWallet(ctx context.Context, tntData *proto.TenantData, sess *data.Session, intent *intents.Intent) error {
	raw, err := json.Marshal(intent.Data)
	if err != nil {
		return fmt.Errorf("encoding intent data: %w", err)
	}
	var target struct {
		Wallet *string `json:"wallet"`
	}
	if err := json.Unmarshal(raw, &target); err != nil {
		return proto.ErrWebrpcBadRequest.WithCausef("decoding intent data: %v", err)
	}
	if target.Wallet == nil {
		return nil
	}
	if !common.IsHexAddress(*target.Wallet) {
		return proto.ErrWebrpcBadRequest.WithCausef("invalid wallet address: %q", *target.Wallet)
	}

	sessionWallet, err := AddressForUser(ctx, tntData, sess.UserID)
	if err != nil {
		return fmt.Errorf("computing session wallet: %w", err)
	}
	if common.HexToAddress(*target.Wallet) != common.HexToAddress(sessionWallet) {
		return proto.ErrUnauthorized.WithCausef("intent wallet does not belong to the session")
	}
	return nil
}
