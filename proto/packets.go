package proto

import (
	"encoding/json"
	"fmt"

	"github.com/0xsequence/go-sequence/intents"
	"github.com/0xsequence/go-sequence/intents/packets"
)

type Packet interface {
	Unmarshal(packet json.RawMessage) error
}

type Payload[T Packet] struct {
	Packet     T
	Code       string
	Session    string
	IntentJSON string
	packetJSON json.RawMessage
}

func ParseIntent(rawIntent *Intent) (*Payload[Packet], error) {
	packetSigs := make([]intents.Signature, len(rawIntent.Signatures))
	for i, sig := range rawIntent.Signatures {
		packetSigs[i].Session = sig.Session
		packetSigs[i].Signature = sig.Signature
	}
	intentJSON, err := json.Marshal(intents.JSONIntent{
		Version:    rawIntent.Version,
		Packet:     rawIntent.Packet,
		Signatures: packetSigs,
	})
	if err != nil {
		return nil, err
	}

	var intent intents.Intent
	if err := json.Unmarshal(intentJSON, &intent); err != nil {
		return nil, fmt.Errorf("intent unmarshal: %w", err)
	}

	if !intent.IsValid() {
		return nil, fmt.Errorf("intent is invalid")
	}

	signers := intent.Signers()
	if len(signers) != 1 {
		return nil, fmt.Errorf("expected exactly one valid signature")
	}

	payload := &Payload[Packet]{
		Code:       intent.PacketCode(),
		Session:    signers[0],
		IntentJSON: string(intentJSON),
		packetJSON: intent.Packet,
	}
	return payload, nil
}

func ParsePacketInPayload[T Packet](payload *Payload[Packet], packet T) (*Payload[T], error) {
	if err := packet.Unmarshal(payload.packetJSON); err != nil {
		return nil, fmt.Errorf("packet unmarshal: %w", err)
	}
	nextPayload := &Payload[T]{
		Packet:     packet,
		Code:       payload.Code,
		Session:    payload.Session,
		IntentJSON: payload.IntentJSON,
	}
	return nextPayload, nil
}

func ParseIntentWithPacket[T Packet](rawIntent *Intent, packet T) (*Payload[T], error) {
	payload, err := ParseIntent(rawIntent)
	if err != nil {
		return nil, err
	}
	return ParsePacketInPayload[T](payload, packet)
}

type ListSessionsPacket struct {
	packets.BasePacketForWallet
}

const ListSessionsPacketCode = "listSessions"

func (p *ListSessionsPacket) Unmarshal(packet json.RawMessage) error {
	err := json.Unmarshal(packet, &p)
	if err != nil {
		return err
	}

	if p.Code != ListSessionsPacketCode {
		return fmt.Errorf("packet code is not '%s', got '%s'", ListSessionsPacketCode, p.Code)
	}

	return nil
}
