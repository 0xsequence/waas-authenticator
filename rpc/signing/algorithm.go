package signing

import (
	"fmt"
)

type Algorithm string

const (
	AlgorithmRsaPkcs1V15Sha256 Algorithm = "rsa-v1_5-sha256"
	AlgorithmRsaPkcs1V15Sha384 Algorithm = "rsa-v1_5-sha384"
	AlgorithmRsaPkcs1V15Sha512 Algorithm = "rsa-v1_5-sha512"
	AlgorithmRsaPssSha256      Algorithm = "rsa-pss-sha256"
	AlgorithmRsaPssSha384      Algorithm = "rsa-pss-sha384"
	AlgorithmRsaPssSha512      Algorithm = "rsa-pss-sha512"
)

var validAlgorithms = map[Algorithm]bool{
	AlgorithmRsaPkcs1V15Sha256: true,
	AlgorithmRsaPkcs1V15Sha384: true,
	AlgorithmRsaPkcs1V15Sha512: true,
	AlgorithmRsaPssSha256:      true,
	AlgorithmRsaPssSha384:      true,
	AlgorithmRsaPssSha512:      true,
}

func (a Algorithm) String() string {
	return string(a)
}

func (a Algorithm) IsValid() bool {
	return validAlgorithms[a]
}

func NewAlgorithm(alg string) (Algorithm, error) {
	a := Algorithm(alg)
	if !a.IsValid() {
		return a, fmt.Errorf("invalid algorithm: %s", alg)
	}
	return a, nil
}
