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

func (s *RPC) SendIntent(ctx context.Context, protoIntent *proto.Intent) (*proto.IntentResponse, error) {
	tntData := tenant.FromContext(ctx)

	intent, sessionID, err := parseIntent(protoIntent)
	if err != nil {
		return nil, err
	}

	sess, found, err := s.Sessions.Get(ctx, tntData.ProjectID, sessionID)
	if err != nil || !found {
		return nil, fmt.Errorf("session invalid or not found")
	}

	walletAddress, err := AddressForUser(ctx, tntData, sess.UserID)
	if err != nil {
		return nil, fmt.Errorf("computing user address: %w", err)
	}

	targetWallet := &proto_wallet.TargetWallet{
		User:    sess.UserID,
		Address: walletAddress,
	}

	switch intent.Name {
	case intents.IntentNameOpenSession:
		return nil, fmt.Errorf("opening a session is unsupported outside of RegisterSession")

	case intents.IntentNameCloseSession:
		intentTyped, err := intents.NewIntentTypedFromIntent[intents.IntentDataCloseSession](intent)
		if err != nil {
			return nil, err
		}
		ok, err := s.dropSession(ctx, sess, intentTyped)
		if err != nil {
			return nil, err
		}
		return makeIntentResponse("sessionClosed", ok), nil

	case intents.IntentNameListSessions:
		intentTyped, err := intents.NewIntentTypedFromIntent[intents.IntentDataListSessions](intent)
		if err != nil {
			return nil, err
		}
		sessions, err := s.listSessions(ctx, sess, intentTyped)
		if err != nil {
			return nil, err
		}
		return makeIntentResponse("sessionsListed", sessions), nil

	case intents.IntentNameSignMessage:
		intentTyped, err := intents.NewIntentTypedFromIntent[intents.IntentDataSignMessage](intent)
		if err != nil {
			return nil, err
		}
		return s.signMessage(ctx, sess, intentTyped)

	case intents.IntentNameSendTransaction:
		intentTyped, err := intents.NewIntentTypedFromIntent[intents.IntentDataSendTransaction](intent)
		if err != nil {
			return nil, err
		}
		return s.sendTransaction(ctx, sess, intentTyped)
	}

	// Generic forwarding of intent, no special handling
	res, err := s.Wallets.SendIntent(waasContext(ctx), targetWallet, convertToAPIIntent(intent))
	if err != nil {
		return nil, fmt.Errorf("sending intent: %w", err)
	}

	return convertIntentResponse(res), nil
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
