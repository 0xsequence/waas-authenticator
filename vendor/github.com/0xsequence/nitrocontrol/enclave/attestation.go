package enclave

import (
	"context"
	"crypto/rsa"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/0xsequence/nitrocontrol/cms"
)

// Attestation represents an open NSM session. It also includes a Document that is the result of
// NSM attestation call. It is able to perform cryptographic operations using the Document as proof
// of authenticity.
//
// NOTE: Attestation must always be Closed manually after use.
type Attestation struct {
	// ReadCloser is an open NSM session. Reading from it returns random bytes.
	io.ReadCloser

	document []byte

	key *rsa.PrivateKey
	kms KMS
}

// DataKey is an AES-256 encryption key in Plaintext and Ciphertext forms.
// It is the result of KMS GenerateDataKey operation.
type DataKey struct {
	// Plaintext is the plain AES-256 key of exactly 32 bytes that can be used for cryptographic operations.
	Plaintext []byte

	// Ciphertext is Plaintext encrypted using KMS.
	Ciphertext []byte
}

// Document returns the cryptographic attestation document acquired from NSM. Its format is described at:
// https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
func (a *Attestation) Document() []byte {
	return a.document
}

// Decrypt requests a decryption operation from KMS on ciphertext. If the key used to encrypt the
// original data is not one of allowedKeyIDs, Decrypt returns an error.
func (a *Attestation) Decrypt(ctx context.Context, ciphertext []byte, allowedKeyIDs []string) ([]byte, error) {
	params := &kms.DecryptInput{
		CiphertextBlob:      ciphertext,
		EncryptionAlgorithm: types.EncryptionAlgorithmSpecSymmetricDefault,
		Recipient: &types.RecipientInfo{
			AttestationDocument:    a.document,
			KeyEncryptionAlgorithm: types.KeyEncryptionMechanismRsaesOaepSha256,
		},
	}
	out, err := a.kms.Decrypt(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("Decrypt KMS call: %w", err)
	}

	// Verify that the key used to decrypt was one of the allowed keys
	if keyID, ok := keyIsAllowed(out.KeyId, allowedKeyIDs); !ok {
		return nil, fmt.Errorf("KMS key not allowed for this operation: %q", keyID)
	}

	if len(out.Plaintext) > 0 {
		return out.Plaintext, nil
	}

	// KMS returns the plaintext encrypted by the public key from attestation request, enveloped in CMS
	plaintext, err := cms.DecryptEnvelopedKey(a.key, out.CiphertextForRecipient)
	if err != nil {
		return nil, fmt.Errorf("plaintext data key decryption: %w", err)
	}
	return plaintext, nil
}

// GenerateDataKey requests a new AES-256 DataKey from KMS. The DataKey contains both the Plaintext key
// that can be used for data encryption, and the Ciphertext (itself encrypted by KMS) that can be sent
// along the encrypted data.
func (a *Attestation) GenerateDataKey(ctx context.Context, keyID string) (*DataKey, error) {
	params := &kms.GenerateDataKeyInput{
		KeyId:   aws.String(keyID),
		KeySpec: types.DataKeySpecAes256,
		Recipient: &types.RecipientInfo{
			AttestationDocument:    a.document,
			KeyEncryptionAlgorithm: types.KeyEncryptionMechanismRsaesOaepSha256,
		},
	}
	out, err := a.kms.GenerateDataKey(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("GenerateDataKey KMS call: %w", err)
	}

	if len(out.Plaintext) > 0 {
		return &DataKey{Plaintext: out.Plaintext, Ciphertext: out.CiphertextBlob}, nil
	}

	// KMS returns the plaintext encrypted by the public key from attestation request, enveloped in CMS
	ciphertext := out.CiphertextBlob
	plaintext, err := cms.DecryptEnvelopedKey(a.key, out.CiphertextForRecipient)
	if err != nil {
		return nil, fmt.Errorf("ciphertext data key decryption: %w", err)
	}

	dk := &DataKey{
		Plaintext:  plaintext,
		Ciphertext: ciphertext,
	}
	return dk, nil
}

func keyIsAllowed(key *string, allowedKeys []string) (string, bool) {
	if key == nil || len(allowedKeys) == 0 {
		return "", true
	}

	for _, v := range allowedKeys {
		if *key == v {
			return v, true
		}
	}

	return *key, false
}
