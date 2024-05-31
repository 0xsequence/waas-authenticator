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

func (s *RPC) sendTransaction(
	ctx context.Context, sess *data.Session, intent *intents.IntentTyped[intents.IntentDataSendTransaction],
) (*proto.IntentResponse, error) {
	tntData := tenant.FromContext(ctx)

	parentWallet, err := ethwallet.NewWalletFromPrivateKey(tntData.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("recovering parent wallet: %w", err)
	}

	// use original intent otherwise we may experience lose of data because of outdated struct
	apiIntent := waasapi.ConvertToAPIIntent(&intent.Intent)
	bundle, err := s.Wallets.GenTransaction(waasapi.Context(ctx), apiIntent)
	if err != nil {
		return nil, fmt.Errorf("generating transaction: %w", err)
	}

	nonce, ok := sequence.ParseHexOrDec(bundle.Nonce)
	if !ok {
		return nil, fmt.Errorf("invalid nonce: %s", bundle.Nonce)
	}

	// Convert bundle.Transaction into sequence.Transaction
	strans := make(sequence.Transactions, len(bundle.Transactions))
	for i, t := range bundle.Transactions {
		val, ok := sequence.ParseHexOrDec(t.Value)
		if !ok {
			return nil, fmt.Errorf("invalid value: %s", t.Value)
		}

		gasLimit, ok := sequence.ParseHexOrDec(t.GasLimit)
		if !ok {
			return nil, fmt.Errorf("invalid gas limit: %s", t.GasLimit)
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
		return nil, fmt.Errorf("calculating transaction bundle digest: %w", err)
	}
	chainID, ok := sequence.ParseHexOrDec(intent.Data.Network)
	if !ok {
		return nil, fmt.Errorf("invalid chain id: %s", intent.Data.Network)
	}

	subdigest, err := sequence.SubDigest(chainID, common.HexToAddress(intent.Data.Wallet), digest)
	if err != nil {
		return nil, fmt.Errorf("calculating subdigest: %w", err)
	}

	// Validate that transactions match intent
	if !intent.Data.IsValidInterpretation(common.Hash(subdigest), strans, nonce) {
		return nil, fmt.Errorf("WaaS API returned incompatible transactions")
	}

	// Our EOA belongs to the *parent* wallet, so we need to sign the subdigest with the parent key
	sig, parentSubdigest, err := s.signUsingParent(parentWallet, tntData.ParentAddress, subdigest, chainID)
	if err != nil {
		return nil, fmt.Errorf("signing subdigest using parent wallet: %w", err)
	}

	signatures := []*proto_wallet.ProvidedSignature{
		{
			Digest:    "0x" + common.Bytes2Hex(parentSubdigest),
			Signature: "0x" + common.Bytes2Hex(sig),
			Address:   parentWallet.Address().String(),
		},
	}

	res, err := s.Wallets.SendTransaction(waasapi.Context(ctx), apiIntent, bundle, signatures)
	if err != nil {
		return nil, fmt.Errorf("sending transaction: %w", err)
	}

	return convertIntentResponse(res), nil
}
