package rpc

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/0xsequence/ethkit/go-ethereum/common"
	"github.com/0xsequence/go-sequence/intents"
	"github.com/0xsequence/waas-authenticator/data"
	"github.com/0xsequence/waas-authenticator/proto"
)

// walletRequired are the intents the parent key signs for a wallet. Without a
// wallet, their handlers would sign for the zero address.
var walletRequired = map[intents.IntentName]bool{
	intents.IntentName_signMessage:      true,
	intents.IntentName_signTypedData:    true,
	intents.IntentName_sendTransaction:  true,
	intents.IntentName_sessionAuthProof: true,
}

// checkIntentWallet rejects an intent that names a wallet other than the
// session user's own. Intents act on the caller's wallet only, and the
// authenticator signs with the tenant's parent key for whichever wallet the
// intent names, so it must not rely on downstream services for this check.
func checkIntentWallet(ctx context.Context, tntData *proto.TenantData, sess *data.Session, intent *intents.Intent) error {
	wallet, err := intentWallet(intent)
	if err != nil {
		return err
	}
	if wallet == nil {
		if walletRequired[intent.Name] {
			return proto.ErrWebrpcBadRequest.WithCausef("intent %s requires a wallet", intent.Name)
		}
		return nil
	}

	sessionWallet, err := AddressForUser(ctx, tntData, sess.UserID)
	if err != nil {
		return fmt.Errorf("computing session wallet: %w", err)
	}
	if common.HexToAddress(*wallet) != common.HexToAddress(sessionWallet) {
		return proto.ErrUnauthorized.WithCausef("intent wallet does not belong to the session")
	}
	return nil
}

// intentWallet returns the wallet the intent names, or nil if it names none.
// The intent handlers decode the data with encoding/json, which matches keys
// case-insensitively and ignores null for strings, so a "Wallet" key next to
// "wallet": null reaches them as a wallet. Only the exact key is accepted
// here, and it must hold an address.
func intentWallet(intent *intents.Intent) (*string, error) {
	raw, err := json.Marshal(intent.Data)
	if err != nil {
		return nil, fmt.Errorf("encoding intent data: %w", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, proto.ErrWebrpcBadRequest.WithCausef("decoding intent data: %v", err)
	}
	for key := range fields {
		if key != "wallet" && strings.EqualFold(key, "wallet") {
			return nil, proto.ErrWebrpcBadRequest.WithCausef("invalid intent data key: %q", key)
		}
	}

	value, ok := fields["wallet"]
	if !ok {
		return nil, nil
	}
	var wallet *string
	if err := json.Unmarshal(value, &wallet); err != nil || wallet == nil {
		return nil, proto.ErrWebrpcBadRequest.WithCausef("invalid wallet: %s", value)
	}
	if !common.IsHexAddress(*wallet) {
		return nil, proto.ErrWebrpcBadRequest.WithCausef("invalid wallet address: %q", *wallet)
	}
	return wallet, nil
}
