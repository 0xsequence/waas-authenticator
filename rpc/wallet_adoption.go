package rpc

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/0xsequence/ethkit/ethwallet"
	"github.com/0xsequence/ethkit/go-ethereum/common"
	"github.com/0xsequence/go-sequence"
	v2 "github.com/0xsequence/go-sequence/core/v2"
	"github.com/0xsequence/go-sequence/intents"
	"github.com/0xsequence/waas-authenticator/data"
	proto_wallet "github.com/0xsequence/waas-authenticator/proto/waas"
	"github.com/0xsequence/waas-authenticator/rpc/tenant"
	"github.com/0xsequence/waas-authenticator/rpc/waasapi"
)

func (s *RPC) adoptChildWallet(
	ctx context.Context, sess *data.Session, intent *intents.IntentTyped[intents.IntentDataAdoptChildWallet],
) (*proto_wallet.IntentResponse, error) {
	tnt := tenant.FromContext(ctx)

	signerWallet, err := ethwallet.NewWalletFromPrivateKey(tnt.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("recovering parent wallet: %w", err)
	}

	if !common.IsHexAddress(intent.Data.Adopter) {
		return nil, fmt.Errorf("invalid adopter: %s", intent.Data.Adopter)
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
	approval := imageHash.Approval()

	subdigest, err := sequence.SubDigest(big.NewInt(0), common.HexToAddress(intent.Data.Wallet), approval)
	if err != nil {
		return nil, fmt.Errorf("calculating digest: %w", err)
	}

	// Our EOA belongs to the *parent* wallet, so we need to sign the subdigest with the parent key
	sig, parentSubdigest, err := s.signUsingParent(signerWallet, tnt.ParentAddress, subdigest, big.NewInt(0))
	if err != nil {
		return nil, fmt.Errorf("signing subdigest using parent wallet: %w", err)
	}

	signatures := []*proto_wallet.ProvidedSignature{
		{
			Digest:    "0x" + common.Bytes2Hex(parentSubdigest),
			Signature: "0x" + common.Bytes2Hex(sig),
			Address:   signerWallet.Address().String(),
		},
	}

	apiIntent := waasapi.ConvertToAPIIntent(&intent.Intent)
	res, err := s.Wallets.AdoptChildWallet(waasapi.Context(ctx), apiIntent, childWalletConfig.Checkpoint_, signatures)
	if err != nil {
		return nil, fmt.Errorf("adopting child wallet: %w", err)
	}
	return res, nil
}
