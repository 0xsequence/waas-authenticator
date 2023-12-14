package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func main() {
	bits := 2048
	// bits := 4096
	rawprivkey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		fmt.Printf("failed to create raw private key: %s\n", err)
		return
	}

	// TODO: lets write the private key and public keys to ./etc/keys/...

	// Private key export
	privPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(rawprivkey),
		},
	)
	fmt.Println("** private key (pem):\n", string(privPem))

	// Public key export
	pubkeyBytes, err := x509.MarshalPKIXPublicKey(&rawprivkey.PublicKey)
	if err != nil {
		log.Fatal(err)
	}
	pubPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubkeyBytes,
		},
	)
	fmt.Println("** public key (pem):\n", string(pubPem))

	// Create JWT key from above private key
	privkey, err := jwk.FromRaw(rawprivkey)
	if err != nil {
		fmt.Printf("failed to create private key: %s\n", err)
		return
	}

	pubkey, err := privkey.PublicKey()
	if err != nil {
		fmt.Printf("failed to create public key:%s\n", err)
		return
	}
	_ = pubkey

	token := jwt.New()
	token.Set("hello", "world") // TODO ... add claims ..

	tokenPayload, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, privkey))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("jwt token:", string(tokenPayload))

	// Below we verify it, just for demonstration purposes..
	err = jwt.Validate(token, jwt.WithAcceptableSkew(1*time.Minute))
	if err != nil {
		log.Fatal(err)
	}

	_, err = jwt.Parse(tokenPayload, jwt.WithKey(jwa.RS256, pubkey))
	if err != nil {
		log.Fatal(err)
	}
}
