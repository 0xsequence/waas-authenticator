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
)

func (s *RPC) sessionAuthProof(
	ctx context.Context,
	sess *data.Session,
	intent *intents.IntentTyped[intents.IntentDataSessionAuthProof],
) (*proto.IntentResponse, error) {
	chainID, ok := sequence.ParseHexOrDec(intent.Data.Network)
	if !ok {
		return nil, fmt.Errorf("invalid chain id: %s", intent.Data.Network)
	}

	message := &proto_wallet.SignMessage{
		ChainID: chainID.String(), // todo: Shall this be configurable?
		Message: "0x" + common.Bytes2Hex(
			[]byte(intents.SessionAuthProofMessage(sess.ID, intent.Data.Wallet, intent.Data.Nonce)),
		),
	}

	signature, err := s.signSessionAuthProof(ctx, intent.Data.Wallet, message, intent)
	if err != nil {
		return nil, fmt.Errorf("signing session register proof message: %w", err)
	}

	return &proto.IntentResponse{
		Code: intents.IntentResponseCodeSessionAuthProof,
		Data: &intents.IntentResponseSessionAuthProof{
			SessionID: sess.ID,
			Network:   chainID.String(),
			Wallet:    intent.Data.Wallet,
			Message:   message.Message,
			Signature: signature,
		},
	}, nil
}

func (s *RPC) signSessionAuthProof(
	ctx context.Context,
	userWallet string,
	message *proto_wallet.SignMessage,
	intent *intents.IntentTyped[intents.IntentDataSessionAuthProof],
) (string, error) {
	tntData := tenant.FromContext(ctx)

	parentWallet, err := ethwallet.NewWalletFromPrivateKey(tntData.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("recovering parent wallet: %w", err)
	}

	// Make sure the message is EIP191 encoded
	msgBytes := sequence.MessageToEIP191(common.FromHex(message.Message))

	// Validate that message match intent
	digest := sequence.MessageDigest(msgBytes)

	chainID, ok := sequence.ParseHexOrDec(message.ChainID)
	if !ok {
		return "", fmt.Errorf("invalid chain id: %s", message.ChainID)
	}

	subdigest, err := sequence.SubDigest(chainID, common.HexToAddress(userWallet), digest)
	if err != nil {
		return "", fmt.Errorf("calculating digest: %w", err)
	}

	// Our EOA belongs to the *parent* wallet, so we need to sign the subdigest with the parent key
	sig, parentSubdigest, err := s.signUsingParent(parentWallet, tntData.ParentAddress, subdigest, chainID)
	if err != nil {
		return "", fmt.Errorf("signing subdigest using parent wallet: %w", err)
	}

	signatures := []*proto_wallet.ProvidedSignature{
		{
			Digest:    "0x" + common.Bytes2Hex(parentSubdigest),
			Signature: "0x" + common.Bytes2Hex(sig),
			Address:   parentWallet.Address().String(),
		},
	}

	proof := &proto_wallet.SessionAuthProof{
		Wallet:     userWallet,
		Message:    message,
		Signatures: signatures,
	}

	// use original intent otherwise we may experience lose of data because of outdated struct
	apiIntent := convertToAPIIntent(&intent.Intent)
	res, err := s.Wallets.SessionAuthProof(waasContext(ctx), apiIntent, proof)
	if err != nil {
		return "", fmt.Errorf("signing message: %w", err)
	}

	// IntentResponse -> IntentResponseSignedMessage
	resTyped, err := intents.NewIntentResponseTypedFromIntentResponse[intents.IntentResponseSignedMessage](&intents.IntentResponse{
		Code: res.Code,
		Data: res.Data,
	})
	if err != nil {
		return "", fmt.Errorf("converting intent response: %w", err)
	}

	return resTyped.Data.Signature, nil
}
