package rpc

import (
	"context"
	"fmt"
	"math/big"
	"net/http"

	"github.com/0xsequence/ethkit/ethcoder"
	"github.com/0xsequence/ethkit/ethwallet"
	"github.com/0xsequence/ethkit/go-ethereum/common"
	ethcrypto "github.com/0xsequence/ethkit/go-ethereum/crypto"
	"github.com/0xsequence/go-sequence"
	v2 "github.com/0xsequence/go-sequence/core/v2"
	"github.com/0xsequence/go-sequence/intents"
	"github.com/0xsequence/go-sequence/intents/packets"
	"github.com/pkg/errors"

	"github.com/0xsequence/waas-authenticator/proto"
	proto_wallet "github.com/0xsequence/waas-authenticator/proto/waas"
	"github.com/0xsequence/waas-authenticator/rpc/crypto"
	"github.com/0xsequence/waas-authenticator/rpc/tenant"
)

func addressForUser(ctx context.Context, tntData *proto.TenantData, user string) (string, error) {
	if len(tntData.UserSalt) != 32 {
		return "", fmt.Errorf("invalid user salt length: %d", len(tntData.UserSalt))
	}

	preimage, err := ethcoder.AbiCoder([]string{"string", "bytes32"}, []any{user, [32]byte(tntData.UserSalt)})
	if err != nil {
		return "", errors.Wrap(err, "failed to encode abi")
	}

	uniqueSalt := ethcoder.Keccak256(preimage)

	childWalletConfig := &v2.WalletConfig{
		Threshold_:  1,
		Checkpoint_: 0,
		Tree: &v2.WalletConfigTreeNode{
			Left: &v2.WalletConfigTreeAddressLeaf{
				Weight:  1,
				Address: tntData.ParentAddress,
			},
			Right: &v2.WalletConfigTreeAddressLeaf{
				Weight:  0,
				Address: common.BytesToAddress(uniqueSalt[12:]),
			},
		},
	}

	imageHash := childWalletConfig.ImageHash()
	seqContext := sequence.WalletContext{
		FactoryAddress:    common.HexToAddress(tntData.SequenceContext.Factory),
		MainModuleAddress: common.HexToAddress(tntData.SequenceContext.MainModule),
	}
	address, err := sequence.AddressFromImageHash(imageHash.String(), seqContext)
	if err != nil {
		return "", errors.Wrap(err, "failed to compute address")
	}

	return address.String(), nil
}

func (s *RPC) GetAddress(ctx context.Context, encryptedPayloadKey string, payloadCiphertext string, payloadSig string) (string, error) {
	tntData := tenant.FromContext(ctx)

	payload, payloadBytes, err := crypto.DecryptPayload[*proto.GetAddressPayload](ctx, tntData, encryptedPayloadKey, payloadCiphertext)
	if err != nil {
		return "", err
	}

	_, sessData, err := s.verifySession(ctx, payload.SessionID, payloadBytes, payloadSig)
	if err != nil {
		return "", err
	}

	return addressForUser(ctx, tntData, sessData.Identity().String())
}

func (s *RPC) SendIntent(ctx context.Context, encryptedPayloadKey string, payloadCiphertext string, payloadSig string) (string, any, error) {
	tntData := tenant.FromContext(ctx)

	payload, payloadBytes, err := crypto.DecryptPayload[*proto.SendIntentPayload](ctx, tntData, encryptedPayloadKey, payloadCiphertext)
	if err != nil {
		return "", nil, err
	}

	_, sessData, err := s.verifySession(ctx, payload.SessionID, payloadBytes, payloadSig)
	if err != nil {
		return "", nil, err
	}

	var intent intents.Intent
	if err := intent.UnmarshalJSON([]byte(payload.IntentJSON)); err != nil {
		return "", nil, err
	}

	waasCtx, err := waasContext(ctx)
	if err != nil {
		return "", nil, err
	}

	parentWallet, err := ethwallet.NewWalletFromPrivateKey(tntData.PrivateKey)
	if err != nil {
		return "", nil, err
	}

	walletAddress, err := addressForUser(ctx, tntData, sessData.Identity().String())
	if err != nil {
		return "", nil, err
	}

	targetWallet := &proto_wallet.TargetWallet{
		User:    sessData.Identity().String(),
		Address: walletAddress,
	}

	switch intent.PacketCode() {
	case packets.SignMessagePacketCode:
		var packet packets.SignMessagePacket
		if err := packet.Unmarshal(intent.Packet); err != nil {
			return "", nil, err
		}

		// Validate that message match intent
		digest := sequence.MessageDigest(common.FromHex(packet.Message))

		chainID, ok := sequence.ParseHexOrDec(packet.Network)
		if !ok {
			return "", nil, fmt.Errorf("invalid chain id: %s", packet.Network)
		}

		subdigest, err := sequence.SubDigest(chainID, common.HexToAddress(packet.Wallet), digest)
		if err != nil {
			return "", nil, err
		}

		isValid := packet.IsValidInterpretation(common.Hash(subdigest))
		if !isValid {
			return "", nil, fmt.Errorf("invalid sign message intent")
		}

		// Our EOA belongs to the *parent* wallet, so we need to sign the subdigest with the parent key
		sig, parentSubdigest, err := s.signUsingParent(parentWallet, tntData.ParentAddress, subdigest, chainID)
		if err != nil {
			return "", nil, err
		}

		signMessage := &proto_wallet.SignMessage{
			ChainID: packet.Network,
			Message: packet.Message,
		}

		signatures := []*proto_wallet.ProvidedSignature{
			{
				Digest:    "0x" + common.Bytes2Hex(parentSubdigest),
				Signature: "0x" + common.Bytes2Hex(sig),
				Address:   parentWallet.Address().String(),
			},
		}

		res, err := s.Wallets.SignMessage(waasCtx, targetWallet, payload.IntentJSON, signMessage, signatures)
		if err != nil {
			return "", nil, err
		}

		return res.Code, res.Data, nil

	case packets.SendTransactionCode:
		bundle, err := s.Wallets.GenTransaction(waasCtx, payload.IntentJSON)
		if err != nil {
			return "", nil, err
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

		var packet packets.SendTransactionsPacket
		if err := packet.Unmarshal(intent.Packet); err != nil {
			return "", nil, err
		}

		// Generate subdigest
		sbundle := sequence.Transaction{
			Transactions: strans,
			Nonce:        nonce,
		}
		digest, err := sbundle.Digest()
		if err != nil {
			return "", nil, err
		}
		chainID, ok := sequence.ParseHexOrDec(packet.Network)
		if !ok {
			return "", nil, fmt.Errorf("invalid chain id: %s", packet.Network)
		}

		subdigest, err := sequence.SubDigest(chainID, common.HexToAddress(packet.Wallet), digest)
		if err != nil {
			return "", nil, err
		}

		// Validate that transactions match intent
		isValid := packet.IsValidInterpretation(common.Hash(subdigest), strans, nonce)
		if !isValid {
			return "", nil, fmt.Errorf("WaaS API returned incompatible transactions")
		}

		// Our EOA belongs to the *parent* wallet, so we need to sign the subdigest with the parent key
		sig, parentSubdigest, err := s.signUsingParent(parentWallet, tntData.ParentAddress, subdigest, chainID)
		if err != nil {
			return "", nil, err
		}

		signatures := []*proto_wallet.ProvidedSignature{
			{
				Digest:    "0x" + common.Bytes2Hex(parentSubdigest),
				Signature: "0x" + common.Bytes2Hex(sig),
				Address:   parentWallet.Address().String(),
			},
		}

		res, err := s.Wallets.SendTransaction(waasCtx, targetWallet, payload.IntentJSON, bundle, signatures)
		if err != nil {
			return "", nil, err
		}

		return res.Code, res.Data, nil
	}

	// Generic forwarding of intent, no special handling
	res, err := s.Wallets.SendIntent(waasCtx, targetWallet, payload.IntentJSON)
	if err != nil {
		return "", nil, err
	}

	return res.Code, res.Data, nil
}

func (s *RPC) signUsingParent(wallet *ethwallet.Wallet, parentAddress common.Address, subdigest []byte, chainId *big.Int) ([]byte, []byte, error) {
	parentSubdigest, err := sequence.SubDigest(chainId, parentAddress, common.BytesToHash(subdigest))
	if err != nil {
		return nil, nil, err
	}

	// Sign parent's subdigest
	// notice we don't use s.key.SignData because it hashes the data again
	sig, err := ethcrypto.Sign(parentSubdigest, wallet.PrivateKey())
	if err != nil {
		return nil, nil, err
	}

	if sig[64] < 27 {
		sig[64] += 27
	}

	// The signature must end with SIG_TYPE_EIP712
	return append(sig, byte(1)), parentSubdigest, nil
}

func waasContext(ctx context.Context, optAccessToken ...string) (context.Context, error) {
	var accessToken string
	if len(optAccessToken) == 1 {
		accessToken = optAccessToken[0]
	} else {
		tntData := tenant.FromContext(ctx)
		accessToken = tntData.WaasAccessToken
	}

	waasHeader := http.Header{}
	waasHeader.Set("authorization", "Bearer "+accessToken)
	waasCtx, err := proto_wallet.WithHTTPRequestHeaders(ctx, waasHeader)
	if err != nil {
		return ctx, err
	}
	return waasCtx, nil
}
