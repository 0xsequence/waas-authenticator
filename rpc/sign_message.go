package rpc

import (
	"context"
	"fmt"

	"github.com/0xsequence/ethkit/ethwallet"
	"github.com/0xsequence/ethkit/go-ethereum/common"
	"github.com/0xsequence/go-sequence"
	"github.com/0xsequence/go-sequence/intents/packets"
	"github.com/0xsequence/waas-authenticator/data"
	"github.com/0xsequence/waas-authenticator/proto"
	proto_wallet "github.com/0xsequence/waas-authenticator/proto/waas"
	"github.com/0xsequence/waas-authenticator/rpc/tenant"
)

func (s *RPC) signMessage(
	ctx context.Context, sess *data.Session, payload *proto.Payload[*packets.SignMessagePacket],
) (string, any, error) {
	tntData := tenant.FromContext(ctx)

	walletAddress, err := AddressForUser(ctx, tntData, sess.UserID)
	if err != nil {
		return "", nil, fmt.Errorf("computing user address: %w", err)
	}

	targetWallet := &proto_wallet.TargetWallet{
		User:    sess.UserID,
		Address: walletAddress,
	}

	parentWallet, err := ethwallet.NewWalletFromPrivateKey(tntData.PrivateKey)
	if err != nil {
		return "", nil, fmt.Errorf("recovering parent wallet: %w", err)
	}

	// Validate that message match intent
	digest := sequence.MessageDigest(common.FromHex(payload.Packet.Message))

	chainID, ok := sequence.ParseHexOrDec(payload.Packet.Network)
	if !ok {
		return "", nil, fmt.Errorf("invalid chain id: %s", payload.Packet.Network)
	}

	subdigest, err := sequence.SubDigest(chainID, common.HexToAddress(payload.Packet.Wallet), digest)
	if err != nil {
		return "", nil, fmt.Errorf("calculating digest: %w", err)
	}

	isValid := payload.Packet.IsValidInterpretation(common.Hash(subdigest))
	if !isValid {
		return "", nil, fmt.Errorf("invalid sign message intent")
	}

	// Our EOA belongs to the *parent* wallet, so we need to sign the subdigest with the parent key
	sig, parentSubdigest, err := s.signUsingParent(parentWallet, tntData.ParentAddress, subdigest, chainID)
	if err != nil {
		return "", nil, fmt.Errorf("signing subdigest using parent wallet: %w", err)
	}

	signMessage := &proto_wallet.SignMessage{
		ChainID: payload.Packet.Network,
		Message: payload.Packet.Message,
	}

	signatures := []*proto_wallet.ProvidedSignature{
		{
			Digest:    "0x" + common.Bytes2Hex(parentSubdigest),
			Signature: "0x" + common.Bytes2Hex(sig),
			Address:   parentWallet.Address().String(),
		},
	}

	res, err := s.Wallets.SignMessage(waasContext(ctx), targetWallet, payload.IntentJSON, signMessage, signatures)
	if err != nil {
		return "", nil, fmt.Errorf("signing message: %w", err)
	}

	return res.Code, res.Data, nil
}