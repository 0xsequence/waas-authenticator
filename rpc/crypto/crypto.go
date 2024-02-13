package crypto

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/0xsequence/nitrocontrol/aescbc"
	"github.com/0xsequence/nitrocontrol/enclave"
	"github.com/0xsequence/waas-authenticator/rpc/attestation"
)

func EncryptData(
	ctx context.Context, att *enclave.Attestation, keyID string, data any,
) (encryptedKey []byte, algorithm string, ciphertext []byte, err error) {
	dk, err := att.GenerateDataKey(ctx, keyID)
	if err != nil {
		return nil, "", nil, err
	}

	plaintext, err := json.Marshal(data)
	if err != nil {
		return nil, "", nil, fmt.Errorf("marshal data: %w", err)
	}

	ciphertext, err = aescbc.Encrypt(att, dk.Plaintext, plaintext)
	if err != nil {
		return nil, "", nil, fmt.Errorf("AES decrypt: %w", err)
	}
	return dk.Ciphertext, "AES-256", ciphertext, nil
}

func DecryptData[T any](
	ctx context.Context, encryptedKey []byte, ciphertext []byte, keyIDs []string,
) (T, []byte, error) {
	var zero T
	att := attestation.FromContext(ctx)

	dk, err := att.Decrypt(ctx, encryptedKey, keyIDs)
	if err != nil {
		return zero, nil, err
	}

	payloadBytes, err := aescbc.Decrypt(dk, ciphertext)
	if err != nil {
		return zero, nil, fmt.Errorf("AES decrypt: %w", err)
	}

	var out T
	if err := json.Unmarshal(payloadBytes, &out); err != nil {
		return zero, nil, fmt.Errorf("unmarshal data: %w", err)
	}
	return out, payloadBytes, nil
}
