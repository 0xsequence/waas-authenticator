package rpc

import (
	"context"
	"fmt"

	"github.com/0xsequence/ethkit/ethwallet"
	"github.com/0xsequence/ethkit/go-ethereum/common"
	"github.com/0xsequence/go-sequence"
	"github.com/0xsequence/go-sequence/intents/packets"
	"github.com/0xsequence/waas-authenticator/data"
	proto_wallet "github.com/0xsequence/waas-authenticator/proto/waas"
	"github.com/0xsequence/waas-authenticator/rpc/tenant"
)

func (s *RPC) sendTransaction(
	ctx context.Context, sess *data.Session, payload *Payload[*packets.SendTransactionsPacket],
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

	bundle, err := s.Wallets.GenTransaction(waasContext(ctx), payload.IntentJSON)
	if err != nil {
		return "", nil, fmt.Errorf("generating transaction: %w", err)
	}

	nonce, ok := sequence.ParseHexOrDec(bundle.Nonce)
	if !ok {
		return "", nil, fmt.Errorf("invalid nonce: %s", bundle.Nonce)
	}

	// Convert bundle.Transaction into sequence.Transaction
	strans := make(sequence.Transactions, len(bundle.Transactions))
	for i, t := range bundle.Transactions {
		val, ok := sequence.ParseHexOrDec(t.Value)
		if !ok {
			return "", nil, fmt.Errorf("invalid value: %s", t.Value)
		}

		gasLimit, ok := sequence.ParseHexOrDec(t.GasLimit)
		if !ok {
			return "", nil, fmt.Errorf("invalid gas limit: %s", t.GasLimit)
		}

		strans[i] = &sequence.Transaction{
			To:            common.HexToAddress(t.To),
			Value:         val,
			GasLimit:      gasLimit,
			RevertOnError: t.RevertOnError,
			DelegateCall:  t.DelegateCall,
			Data:          common.FromHex(t.Data),
		}
	}

	// Generate subdigest
	sbundle := sequence.Transaction{
		Transactions: strans,
		Nonce:        nonce,
	}
	digest, err := sbundle.Digest()
	if err != nil {
		return "", nil, fmt.Errorf("calculating transaction bundle digest: %w", err)
	}
	chainID, ok := sequence.ParseHexOrDec(payload.Packet.Network)
	if !ok {
		return "", nil, fmt.Errorf("invalid chain id: %s", payload.Packet.Network)
	}

	subdigest, err := sequence.SubDigest(chainID, common.HexToAddress(payload.Packet.Wallet), digest)
	if err != nil {
		return "", nil, fmt.Errorf("calculating subdigest: %w", err)
	}

	// Validate that transactions match intent
	isValid := payload.Packet.IsValidInterpretation(common.Hash(subdigest), strans, nonce)
	if !isValid {
		return "", nil, fmt.Errorf("WaaS API returned incompatible transactions")
	}

	// Our EOA belongs to the *parent* wallet, so we need to sign the subdigest with the parent key
	sig, parentSubdigest, err := s.signUsingParent(parentWallet, tntData.ParentAddress, subdigest, chainID)
	if err != nil {
		return "", nil, fmt.Errorf("signing subdigest using parent wallet: %w", err)
	}

	signatures := []*proto_wallet.ProvidedSignature{
		{
			Digest:    "0x" + common.Bytes2Hex(parentSubdigest),
			Signature: "0x" + common.Bytes2Hex(sig),
			Address:   parentWallet.Address().String(),
		},
	}

	res, err := s.Wallets.SendTransaction(waasContext(ctx), targetWallet, payload.IntentJSON, bundle, signatures)
	if err != nil {
		return "", nil, fmt.Errorf("sending transaction: %w", err)
	}

	return res.Code, res.Data, nil
}
