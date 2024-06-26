package intents

import (
	"fmt"
	"time"

	"github.com/0xsequence/ethkit/go-ethereum/crypto"
	"github.com/gibson042/canonicaljson-go"
)

const IntentValidTimeInSec = 60
const IntentAllowedTimeDriftInSec = 5

type IntentDataValidator interface {
	IsValid() error
}

func (intent *Intent) Hash() ([]byte, error) {
	// copy intent and remove signatures
	var intentCopy = *intent
	intentCopy.Signatures = nil

	// Convert packet to bytes
	packetBytes, err := canonicaljson.Marshal(intentCopy)
	if err != nil {
		return nil, err
	}

	// Calculate keccak256 hash
	return crypto.Keccak256(packetBytes), nil
}

func (intent *Intent) IsValid() error {
	if len(intent.Signatures) == 0 {
		return fmt.Errorf("no signatures")
	}

	// check if the intent is expired
	if intent.ExpiresAt+IntentAllowedTimeDriftInSec < uint64(time.Now().Unix()) {
		return fmt.Errorf("intent expired")
	}

	// check if the intent is issued in the future
	if intent.IssuedAt-IntentAllowedTimeDriftInSec > uint64(time.Now().Unix()) {
		return fmt.Errorf("intent issued in the future")
	}

	// check if all signatures are valid
	if validSingers := len(intent.Signers()); validSingers == 0 || validSingers != len(intent.Signatures) {
		return fmt.Errorf("invalid signature")
	}

	// the intent is valid
	return nil
}

func (intent *Intent) Signers() []string {
	var signers []string
	for _, signature := range intent.Signatures {
		if err := IsValidSessionSignature(signature.SessionID, signature.Signature, intent); err == nil {
			signers = append(signers, signature.SessionID)
		}
	}
	return signers
}

// IntentName stringer helper method, even thought IntentName is a string type, it's useful to
// have a String() method to satisfy the fmt.Stringer interface
func (n IntentName) String() string {
	return string(n)
}
