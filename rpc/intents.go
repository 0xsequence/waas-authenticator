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
	"github.com/0xsequence/go-sequence/intents/packets"
	"github.com/0xsequence/waas-authenticator/proto"
	proto_wallet "github.com/0xsequence/waas-authenticator/proto/waas"
	"github.com/0xsequence/waas-authenticator/rpc/tenant"
)

func AddressForUser(ctx context.Context, tntData *proto.TenantData, user string) (string, error) {
	if len(tntData.UserSalt) != 32 {
		return "", fmt.Errorf("invalid user salt length: %d", len(tntData.UserSalt))
	}

	preimage, err := ethcoder.AbiCoder([]string{"string", "bytes32"}, []any{user, [32]byte(tntData.UserSalt)})
	if err != nil {
		return "", fmt.Errorf("failed to encode abi: %w", err)
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
		return "", fmt.Errorf("failed to compute address: %w", err)
	}

	return address.String(), nil
}

func (s *RPC) SendIntentV1(ctx context.Context, intent *proto.Intent) (string, any, error) {
	tntData := tenant.FromContext(ctx)

	payload, err := proto.ParseIntent(intent)
	if err != nil {
		return "", nil, fmt.Errorf("parse intent: %w", err)
	}

	sess, found, err := s.Sessions.Get(ctx, tntData.ProjectID, payload.Session)
	if err != nil || !found {
		return "", nil, fmt.Errorf("session invalid or not found")
	}

	walletAddress, err := AddressForUser(ctx, tntData, sess.UserID)
	if err != nil {
		return "", nil, fmt.Errorf("computing user address: %w", err)
	}

	targetWallet := &proto_wallet.TargetWallet{
		User:    sess.UserID,
		Address: walletAddress,
	}

	switch payload.Code {
	case packets.OpenSessionPacketCode:
		return "", nil, fmt.Errorf("opening a session is unsupported outside of RegisterSession")

	case packets.CloseSessionPacketCode:
		payload, err := proto.ParsePacketInPayload(payload, &packets.CloseSessionPacket{})
		if err != nil {
			return "", nil, err
		}
		ok, err := s.dropSession(ctx, sess, payload)
		if err != nil {
			return "", nil, err
		}
		return "sessionClosed", ok, nil

	case proto.ListSessionsPacketCode:
		payload, err := proto.ParsePacketInPayload(payload, &proto.ListSessionsPacket{})
		if err != nil {
			return "", nil, err
		}
		sessions, err := s.listSessions(ctx, sess, payload)
		if err != nil {
			return "", nil, err
		}
		return "sessionsListed", sessions, nil

	case packets.SignMessagePacketCode:
		payload, err := proto.ParsePacketInPayload(payload, &packets.SignMessagePacket{})
		if err != nil {
			return "", nil, err
		}
		return s.signMessage(ctx, sess, payload)

	case packets.SendTransactionCode:
		payload, err := proto.ParsePacketInPayload(payload, &packets.SendTransactionsPacket{})
		if err != nil {
			return "", nil, err
		}
		return s.sendTransaction(ctx, sess, payload)
	}

	// Generic forwarding of intent, no special handling
	res, err := s.Wallets.SendIntent(waasContext(ctx), targetWallet, payload.IntentJSON)
	if err != nil {
		return "", nil, fmt.Errorf("sending intent: %w", err)
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

func waasContext(ctx context.Context, optJwtToken ...string) context.Context {
	var jwtToken string
	if len(optJwtToken) == 1 {
		jwtToken = optJwtToken[0]
	} else {
		tntData := tenant.FromContext(ctx)
		jwtToken = tntData.WaasAccessToken
	}

	waasHeader := http.Header{}
	waasHeader.Set("Authorization", "BEARER "+jwtToken)

	accessKey := tenant.AccessKeyFromContext(ctx)
	if accessKey != "" {
		waasHeader.Set("X-Access-Key", accessKey)
	}

	waasCtx, err := proto_wallet.WithHTTPRequestHeaders(ctx, waasHeader)
	if err != nil {
		return ctx
	}
	return waasCtx
}
