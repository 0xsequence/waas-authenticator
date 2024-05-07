package rpc

import (
	"context"
	"fmt"

	"github.com/0xsequence/go-sequence/intents"
	"github.com/0xsequence/waas-authenticator/proto"
	api "github.com/0xsequence/waas-authenticator/proto/waas"
)

func (s *RPC) ChainList(ctx context.Context) ([]*proto.Chain, error) {
	chains, err := s.Wallets.ChainList(waasContext(ctx))
	if err != nil {
		return nil, err
	}

	var retChain []*proto.Chain
	for _, chain := range chains {
		retChain = append(retChain, &proto.Chain{
			Id:   chain.Id,
			Name: chain.Name,
		})
	}
	return retChain, nil
}

func parseIntent(pi *proto.Intent) (*intents.Intent, string, error) {
	intent := &intents.Intent{
		Version:    pi.Version,
		Name:       intents.IntentName(pi.Name),
		IssuedAt:   pi.IssuedAt,
		ExpiresAt:  pi.ExpiresAt,
		Data:       pi.Data,
		Signatures: convertProtoSignaturesToSignatures(pi.Signatures),
	}

	if err := intent.IsValid(); err != nil {
		return nil, "", fmt.Errorf("intent is invalid: %w", err)
	}

	signers := intent.Signers()
	if len(signers) != 1 {
		return nil, "", fmt.Errorf("expected exactly one valid signature")
	}

	return intent, signers[0], nil
}

func convertProtoSignaturesToSignatures(signatures []*proto.Signature) []*intents.Signature {
	result := make([]*intents.Signature, len(signatures))
	for i, s := range signatures {
		result[i] = &intents.Signature{
			SessionID: s.SessionID,
			Signature: s.Signature,
		}
	}
	return result
}

func convertToAPIIntent(intent *intents.Intent) *api.Intent {
	signatures := make([]*api.Signature, len(intent.Signatures))
	for i, s := range intent.Signatures {
		signatures[i] = &api.Signature{
			SessionID: s.SessionID,
			Signature: s.Signature,
		}
	}
	return &api.Intent{
		Version:    intent.Version,
		Name:       intent.Name.String(),
		ExpiresAt:  intent.ExpiresAt,
		IssuedAt:   intent.IssuedAt,
		Data:       intent.Data,
		Signatures: signatures,
	}
}

func convertIntentResponse(res *api.IntentResponse) *proto.IntentResponse {
	return &proto.IntentResponse{
		Code: proto.IntentResponseCode(res.Code),
		Data: res.Data,
	}
}

func makeIntentResponse(code string, data any) *proto.IntentResponse {
	return &proto.IntentResponse{
		Code: proto.IntentResponseCode(code),
		Data: data,
	}
}
