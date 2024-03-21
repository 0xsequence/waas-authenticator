package rpc

import (
	"context"
	"fmt"

	"github.com/0xsequence/ethkit/go-ethereum/common"
	"github.com/0xsequence/go-sequence/intents"
	"github.com/0xsequence/waas-authenticator/data"
	"github.com/0xsequence/waas-authenticator/proto"
	proto_wallet "github.com/0xsequence/waas-authenticator/proto/waas"
)

func (s *RPC) sessionAuthProof(
	ctx context.Context,
	sess *data.Session,
	intent *intents.IntentTyped[intents.IntentDataSessionAuthProof],
) (*proto.IntentResponse, error) {
	proof := &proto_wallet.SessionAuthProof{
		Wallet: intent.Data.Wallet,
		Message: &proto_wallet.SignMessage{
			ChainID: intent.Data.Network,
			Message: "0x" + common.Bytes2Hex(
				[]byte(intents.SessionAuthProofMessage(sess.ID, intent.Data.Wallet, intent.Data.Nonce)),
			),
		},
	}

	err := s.signSessionAuthProof(ctx, intent.Data.Wallet, proof)
	if err != nil {
		return nil, fmt.Errorf("signing session register proof message: %w", err)
	}

	apiIntent := convertToAPIIntent(&intent.Intent)
	res, err := s.Wallets.SessionAuthProof(waasContext(ctx), apiIntent, proof)
	if err != nil {
		return nil, fmt.Errorf("signing message: %w", err)
	}

	return convertIntentResponse(res), nil
}
