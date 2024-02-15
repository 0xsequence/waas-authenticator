// Package aescbc contains utility functions to Encrypt and Decrypt data using AES-256-CBC cipher.
package aescbc

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
)

// Decrypt decrypts ciphertext using the given key. Key must be a valid AES-256 key with a length of 32 bytes.
// Ciphertext is assumed to be a concatenation of an IV (equal in size to the AES block size) and the actual
// ciphertext. As such, it must be at least aes.BlockSize bytes long.
func Decrypt(key []byte, ciphertext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes for AES-256 but was %d", len(key))
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext must be at least %d bytes but was %d", aes.BlockSize, len(ciphertext))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	decrypter := cipher.NewCBCDecrypter(block, iv)

	plaintextData := make([]byte, len(ciphertext))
	decrypter.CryptBlocks(plaintextData, ciphertext)

	plaintextData, err = pkcs7Unpad(plaintextData)
	if err != nil {
		return nil, fmt.Errorf("pkcs7 unpad: %w", err)
	}
	return plaintextData, nil
}

// Encrypt encrypts plaintext using key and random entropy. Key must be a valid AES-256 key with a length of 32 bytes.
// The result is a concatenation of IV (equal in size to the AES block size) and the actual ciphertext.
func Encrypt(random io.Reader, key []byte, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes for AES-256 but was %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}

	plaintext = pkcs7Pad(plaintext)
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(random, iv); err != nil {
		return nil, fmt.Errorf("generate random IV: %w", err)
	}

	encrypter := cipher.NewCBCEncrypter(block, iv)
	encrypter.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)
	return ciphertext, nil
}

// PKCS7 unpadding
func pkcs7Unpad(data []byte) ([]byte, error) {
	padding := int(data[len(data)-1])
	if padding < 1 || padding > aes.BlockSize {
		return nil, fmt.Errorf("invalid padding")
	}
	return data[:len(data)-padding], nil
}

// PKCS7 padding
func pkcs7Pad(data []byte) []byte {
	padLen := aes.BlockSize - len(data)%aes.BlockSize
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, padding...)
}
