package rpc

import (
	"context"
	"fmt"
	"math/big"

	"github.com/0xsequence/ethkit/ethcoder"
	"github.com/0xsequence/ethkit/ethwallet"
	"github.com/0xsequence/ethkit/go-ethereum/common"
	ethcrypto "github.com/0xsequence/ethkit/go-ethereum/crypto"
	"github.com/0xsequence/go-sequence"
	v2 "github.com/0xsequence/go-sequence/core/v2"
	"github.com/0xsequence/go-sequence/intents"
	"github.com/0xsequence/waas-authenticator/proto"
	"github.com/0xsequence/waas-authenticator/rpc/tenant"
	"github.com/0xsequence/waas-authenticator/rpc/tracing"
	"github.com/0xsequence/waas-authenticator/rpc/waasapi"
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

	ctx, span := tracing.Intent(ctx, intent)
	defer span.End()

	if intent.Name == intents.IntentName_initiateAuth {
		intentTyped, err := intents.NewIntentTypedFromIntent[intents.IntentDataInitiateAuth](intent)
		if err != nil {
			return nil, err
		}
		res, err := s.initiateAuth(ctx, intentTyped)
		if err != nil {
			return nil, err
		}
		return makeIntentResponse(proto.IntentResponseCode_authInitiated, res), nil
	}

	sess, found, err := s.Sessions.Get(ctx, tntData.ProjectID, sessionID)
	if (err != nil || !found) && intent.Name != intents.IntentName_closeSession {
		return nil, fmt.Errorf("session invalid or not found")
	}

	switch intent.Name {
	case intents.IntentName_openSession:
		return nil, fmt.Errorf("opening a session is unsupported outside of RegisterSession")

	case intents.IntentName_closeSession:
		intentTyped, err := intents.NewIntentTypedFromIntent[intents.IntentDataCloseSession](intent)
		if err != nil {
			return nil, err
		}
		_, err = s.dropSession(ctx, sess, intentTyped)
		if err != nil {
			return nil, err
		}
		return makeIntentResponse(proto.IntentResponseCode_sessionClosed, intents.IntentResponseSessionClosed{}), nil

	case intents.IntentName_listSessions:
		intentTyped, err := intents.NewIntentTypedFromIntent[intents.IntentDataListSessions](intent)
		if err != nil {
			return nil, err
		}
		sessions, err := s.listSessions(ctx, sess, intentTyped)
		if err != nil {
			return nil, err
		}
		return makeIntentResponse(proto.IntentResponseCode_sessionList, sessions), nil

	case intents.IntentName_sessionAuthProof:
		intentTyped, err := intents.NewIntentTypedFromIntent[intents.IntentDataSessionAuthProof](intent)
		if err != nil {
			return nil, err
		}
		return s.sessionAuthProof(ctx, sess, intentTyped)

	case intents.IntentName_signMessage:
		intentTyped, err := intents.NewIntentTypedFromIntent[intents.IntentDataSignMessage](intent)
		if err != nil {
			return nil, err
		}
		return s.signMessage(ctx, sess, intentTyped)

	case intents.IntentName_sendTransaction:
		intentTyped, err := intents.NewIntentTypedFromIntent[intents.IntentDataSendTransaction](intent)
		if err != nil {
			return nil, err
		}
		return s.sendTransaction(ctx, sess, intentTyped)

	case intents.IntentName_listAccounts:
		intentTyped, err := intents.NewIntentTypedFromIntent[intents.IntentDataListAccounts](intent)
		if err != nil {
			return nil, err
		}
		accounts, err := s.listAccounts(ctx, sess, intentTyped)
		if err != nil {
			return nil, err
		}
		return makeIntentResponse(proto.IntentResponseCode_accountList, accounts), nil

	case intents.IntentName_federateAccount:
		intentTyped, err := intents.NewIntentTypedFromIntent[intents.IntentDataFederateAccount](intent)
		if err != nil {
			return nil, err
		}
		account, err := s.federateAccount(ctx, sess, intentTyped)
		if err != nil {
			return nil, err
		}
		return makeIntentResponse(proto.IntentResponseCode_accountFederated, account), nil

	case intents.IntentName_removeAccount:
		intentTyped, err := intents.NewIntentTypedFromIntent[intents.IntentDataRemoveAccount](intent)
		if err != nil {
			return nil, err
		}
		if err := s.removeAccount(ctx, sess, intentTyped); err != nil {
			return nil, err
		}
		return makeIntentResponse(proto.IntentResponseCode_accountRemoved, true), nil

	case intents.IntentName_getIdToken:
		intentTyped, err := intents.NewIntentTypedFromIntent[intents.IntentDataGetIdToken](intent)
		if err != nil {
			return nil, err
		}
		res, err := s.getIDToken(ctx, sess, intentTyped)
		if err != nil {
			return nil, err
		}
		return makeIntentResponse(proto.IntentResponseCode_idToken, res), nil
	}

	// Generic forwarding of intent, no special handling
	res, err := s.Wallets.SendIntent(waasapi.Context(ctx), waasapi.ConvertToAPIIntent(intent))
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
