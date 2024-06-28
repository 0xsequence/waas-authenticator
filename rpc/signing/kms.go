package signing

import (
	"context"
	"crypto/md5"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type KMS struct {
	Client     *kms.Client
	SigningKey string
}

func NewKMS(kmsClient *kms.Client, signingKey string) Signer {
	return &KMS{
		Client:     kmsClient,
		SigningKey: signingKey,
	}
}

func (p *KMS) Sign(ctx context.Context, alg Algorithm, message []byte) ([]byte, error) {

	var spec types.SigningAlgorithmSpec
	switch alg {
	case AlgorithmRsaPssSha256:
		spec = types.SigningAlgorithmSpecRsassaPssSha256
	case AlgorithmRsaPssSha384:
		spec = types.SigningAlgorithmSpecRsassaPssSha384
	case AlgorithmRsaPssSha512:
		spec = types.SigningAlgorithmSpecRsassaPssSha512
	case AlgorithmRsaPkcs1V15Sha256:
		spec = types.SigningAlgorithmSpecRsassaPkcs1V15Sha256
	case AlgorithmRsaPkcs1V15Sha384:
		spec = types.SigningAlgorithmSpecRsassaPkcs1V15Sha384
	case AlgorithmRsaPkcs1V15Sha512:
		spec = types.SigningAlgorithmSpecRsassaPkcs1V15Sha512
	default:
		return nil, fmt.Errorf("unknown signing algorithm: %v", alg)
	}

	out, err := p.Client.Sign(ctx, &kms.SignInput{
		KeyId:            &p.SigningKey,
		Message:          message,
		SigningAlgorithm: spec,
		MessageType:      types.MessageTypeRaw,
	})
	if err != nil {
		return nil, err
	}
	return out.Signature, nil
}

func (p *KMS) PublicKey(ctx context.Context) (jwk.RSAPublicKey, error) {
	out, err := p.Client.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: &p.SigningKey,
	})
	if err != nil {
		return nil, err
	}

	rawKey, err := x509.ParsePKIXPublicKey(out.PublicKey)
	if err != nil {
		return nil, err
	}

	jwtKey, err := jwk.FromRaw(rawKey)
	if err != nil {
		return nil, err
	}

	pubKey, ok := jwtKey.(jwk.RSAPublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid public key type: %T", jwtKey)
	}
	_ = pubKey.Set(jwk.KeyIDKey, p.KeyID())
	return pubKey, nil
}

func (p *KMS) KeyID() string {
	h := md5.New()
	h.Write([]byte(p.SigningKey))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
