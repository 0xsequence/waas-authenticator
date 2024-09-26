package rpc

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/0xsequence/ethkit/ethcoder"
	"github.com/0xsequence/ethkit/ethwallet"
	"github.com/0xsequence/ethkit/go-ethereum/common"
	"github.com/0xsequence/go-sequence"
	v2 "github.com/0xsequence/go-sequence/core/v2"
	"github.com/0xsequence/go-sequence/intents"
	"github.com/0xsequence/waas-authenticator/data"
	"github.com/0xsequence/waas-authenticator/rpc/tenant"
)

// _SetImageHashPrefix = keccak256("SetImageHash(bytes32 imageHash)")
const _SetImageHashPrefix = "0x8713a7c4465f6fbee2b6e9d6646d1d9f83fec929edfc4baf661f3c865bdd04d1"

func (s *RPC) adoptChildWallet(
	ctx context.Context, sess *data.Session, intent *intents.IntentTyped[intents.IntentDataAdoptChildWallet],
) error {
	tnt := tenant.FromContext(ctx)

	parentWallet, err := ethwallet.NewWalletFromPrivateKey(tnt.PrivateKey)
	if err != nil {
		return fmt.Errorf("recovering parent wallet: %w", err)
	}

	// TODO: verify adopter signature

	if !common.IsHexAddress(intent.Data.Adopter) {
		return fmt.Errorf("invalid adopter: %s", intent.Data.Adopter)
	}

	adopterAddress := common.HexToAddress(intent.Data.Adopter)
	childWalletConfig := &v2.WalletConfig{
		Threshold_:  1,
		Checkpoint_: uint32(time.Now().Unix()),
		Tree: &v2.WalletConfigTreeNode{
			Left: &v2.WalletConfigTreeAddressLeaf{
				Weight:  1,
				Address: tnt.ParentAddress,
			},
			Right: &v2.WalletConfigTreeAddressLeaf{
				Weight:  2,
				Address: adopterAddress,
			},
		},
	}
	imageHash := childWalletConfig.ImageHash()

	setImageHashMessage, err := ethcoder.SolidityPack(
		[]string{"bytes32", "bytes32"},
		[]any{common.Hex2Bytes(_SetImageHashPrefix), imageHash.Bytes()},
	)
	if err != nil {
		return fmt.Errorf("solidity pack: %w", err)
	}
	setImageHashMessageHash := ethcoder.Keccak256(setImageHashMessage)

	// Make sure the message is EIP191 encoded
	msgBytes := sequence.MessageToEIP191(setImageHashMessageHash)

	sig, parentSubdigest, err := s.signUsingParent(parentWallet, tnt.ParentAddress, msgBytes, big.NewInt(1))
	if err != nil {
		return fmt.Errorf("sign using parent: %w", err)
	}

}
