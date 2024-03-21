package rpc

import (
	"context"
	"fmt"

	"github.com/0xsequence/ethkit/ethwallet"
	"github.com/0xsequence/ethkit/go-ethereum/common"
	"github.com/0xsequence/go-sequence"
	proto_wallet "github.com/0xsequence/waas-authenticator/proto/waas"
	"github.com/0xsequence/waas-authenticator/rpc/tenant"
)

func (s *RPC) signSessionAuthProof(
	ctx context.Context,
	userWallet string,
	proof *proto_wallet.SessionAuthProof,
) error {
	tntData := tenant.FromContext(ctx)

	parentWallet, err := ethwallet.NewWalletFromPrivateKey(tntData.PrivateKey)
	if err != nil {
		return fmt.Errorf("recovering parent wallet: %w", err)
	}

	// Make sure the message is EIP191 encoded
	msgBytes := sequence.MessageToEIP191(common.FromHex(proof.Message.Message))

	// Validate that message match intent
	digest := sequence.MessageDigest(msgBytes)

	chainID, ok := sequence.ParseHexOrDec(proof.Message.ChainID)
	if !ok {
		return fmt.Errorf("invalid chain id: %s", proof.Message.ChainID)
	}

	subdigest, err := sequence.SubDigest(chainID, common.HexToAddress(userWallet), digest)
	if err != nil {
		return fmt.Errorf("calculating digest: %w", err)
	}

	// Our EOA belongs to the *parent* wallet, so we need to sign the subdigest with the parent key
	sig, parentSubdigest, err := s.signUsingParent(parentWallet, tntData.ParentAddress, subdigest, chainID)
	if err != nil {
		return fmt.Errorf("signing subdigest using parent wallet: %w", err)
	}

	proof.Signatures = []*proto_wallet.ProvidedSignature{
		{
			Digest:    "0x" + common.Bytes2Hex(parentSubdigest),
			Signature: "0x" + common.Bytes2Hex(sig),
			Address:   parentWallet.Address().String(),
		},
	}
	return nil
}
