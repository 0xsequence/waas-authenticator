package rpc

import (
	"context"
	"fmt"

	"github.com/0xsequence/ethkit/ethwallet"
	"github.com/0xsequence/ethkit/go-ethereum/common"
	"github.com/0xsequence/go-sequence"
	"github.com/0xsequence/go-sequence/intents"
	"github.com/0xsequence/waas-authenticator/data"
	"github.com/0xsequence/waas-authenticator/proto"
	proto_wallet "github.com/0xsequence/waas-authenticator/proto/waas"
	"github.com/0xsequence/waas-authenticator/rpc/tenant"
	"github.com/0xsequence/waas-authenticator/rpc/waasapi"
)

func (s *RPC) signTypedData(
	ctx context.Context, sess *data.Session, intent *intents.IntentTyped[intents.IntentDataSignTypedData],
) (*proto.IntentResponse, error) {
	tntData := tenant.FromContext(ctx)

	parentWallet, err := ethwallet.NewWalletFromPrivateKey(tntData.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("recovering parent wallet: %w", err)
	}

	chainID, ok := sequence.ParseHexOrDec(intent.Data.Network)
	if !ok {
		return nil, fmt.Errorf("invalid chain id: %s", intent.Data.Network)
	}

	_, encodedMessage, err := intent.Data.TypedData.Encode()
	if err != nil {
		return nil, fmt.Errorf("encoding typed data: %w", err)
	}

	digest := sequence.MessageDigest(encodedMessage)

	subdigest, err := sequence.SubDigest(chainID, common.HexToAddress(intent.Data.Wallet), digest)
	if err != nil {
		return nil, fmt.Errorf("calculating digest: %w", err)
	}

	if !intent.Data.IsValidInterpretation(common.Hash(subdigest)) {
		return nil, fmt.Errorf("invalid signTypedData intent")
	}

	// Our EOA belongs to the *parent* wallet, so we need to sign the subdigest with the parent key
	sig, parentSubdigest, err := s.signUsingParent(parentWallet, tntData.ParentAddress, subdigest, chainID)
	if err != nil {
		return nil, fmt.Errorf("signing subdigest using parent wallet: %w", err)
	}

	signTypedData := &proto_wallet.SignTypedData{
		ChainID:   intent.Data.Network,
		TypedData: intent.Data.TypedData,
	}

	signatures := []*proto_wallet.ProvidedSignature{
		{
			Digest:    "0x" + common.Bytes2Hex(parentSubdigest),
			Signature: "0x" + common.Bytes2Hex(sig),
			Address:   parentWallet.Address().String(),
		},
	}

	// use original intent otherwise we may experience lose of data because of outdated struct
	apiIntent := waasapi.ConvertToAPIIntent(&intent.Intent)
	res, err := s.Wallets.SignTypedData(waasapi.Context(ctx), apiIntent, signTypedData, signatures)
	if err != nil {
		return nil, fmt.Errorf("signing typed data: %w", err)
	}

	return convertIntentResponse(res), nil
}
